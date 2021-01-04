/*
 * net/sched/sch_ftbf.c    Fair Token Bucket Filter queue.
 *
 *        This program is free software; you can redistribute it and/or
 *        modify it under the terms of the GNU General Public License
 *        as published by the Free Software Foundation; either version
 *        2 of the License, or (at your option) any later version.
 *
 * Authors:    Danfeng Shan, <shandanf@gmail.com>
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/stat.h>
#include <linux/limits.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/netlink.h>
#include <net/sch_generic.h>
#include <net/pkt_sched.h>


/* F-TBF section */
#define MAX_SKETCH_DEPTH 8
#define MAX_SKETCH_WIDTH 100000
#define MAX_QUEUE_DEPTH 2000
#define FTBF_DEBUG 0

struct ftbf_flow_id {
    u32 flow_hash[MAX_SKETCH_DEPTH];
};

struct active_flow_queue {
    struct ftbf_flow_id que[MAX_QUEUE_DEPTH];
    u32 head; // head of active queue
    u32 tail; // tail of active queue
    u32 len; // length of active queue
};

struct tc_ftbf_qopt {
    struct tc_ratespec rate;
    struct tc_ratespec peakrate;
    __u32        limit;
    __u32        buffer;
    __u32        mtu;
};

enum {
    TCA_FTBF_UNSPEC,
    TCA_FTBF_PARMS,
    TCA_FTBF_RTAB,
    TCA_FTBF_PTAB,
    TCA_FTBF_RATE64,
    TCA_FTBF_PRATE64,
    TCA_FTBF_BURST,
    TCA_FTBF_PBURST,
    TCA_FTBF_PAD,
    __TCA_FTBF_MAX,
};

#define TCA_FTBF_MAX (__TCA_FTBF_MAX - 1)

struct ftbf_sched_data {
/* Parameters */
    u32 limit;        /* Maximal length of backlog: bytes */
    u32 max_size;
    s64 buffer;        /* Token bucket depth/rate: MUST BE >= MTU/B */
    s64 mtu;
    struct psched_ratecfg rate;
    struct psched_ratecfg peak;

    s32 alpha_shift;

/* Variables */
    s64    tokens;            /* Current number of B tokens */
    s64    ptokens;        /* Current number of P tokens */
    s64    t_c;            /* Time check-point */
    struct Qdisc    *qdisc;        /* Inner qdisc, default - bfifo queue */
    struct qdisc_watchdog watchdog;    /* Watchdog timer */

    /* Parameters for F-TBF */
    u64 *token_occupied_bytes[MAX_SKETCH_DEPTH];
    // u64 *token_used_bytes[MAX_SKETCH_DEPTH];
    // u64 *token_returned_bytes[MAX_SKETCH_DEPTH];
    siphash_key_t sketch_perturbation[MAX_SKETCH_DEPTH];
    struct active_flow_queue active_q;
    u64 aq_last_dequeue_time; // last dequeue time of active queue
};


static unsigned int flow_burst_bytes = UINT_MAX;
module_param(flow_burst_bytes, uint, 0444);
MODULE_PARM_DESC(flow_burst_bytes, "The maximum burst (in bytes) allowed for a single flow.");

static unsigned int sketch_depth = 4;
module_param(sketch_depth, uint, 0444);
MODULE_PARM_DESC(sketch_depth, "The depth of sketch.");

static unsigned int sketch_width = 1024;
module_param(sketch_width, uint, 0444);
MODULE_PARM_DESC(sketch_width, "The width of sketch.");

static int alpha_shift = 0;
module_param(alpha_shift, int, 0444);
MODULE_PARM_DESC(alpha_shift, "The shifted value of alpha (alpha = (1 / 2^alpha).");

static int token_alloc_bytes = 100;
module_param(token_alloc_bytes, int, 0444);
MODULE_PARM_DESC(token_alloc_bytes, "Minimum size of tokens allocated to each flow.");

static void ftbf_reset_active_queue(struct ftbf_sched_data *q)
{
    q->active_q.head = 0;
    q->active_q.tail = 0;
    q->active_q.len = 0;
    q->aq_last_dequeue_time = ktime_get_ns();
}

static void ftbf_reset_sketch(struct ftbf_sched_data *q)
{
    unsigned int i;
    for (i = 0; i < sketch_depth; ++i) {
        memset(q->token_occupied_bytes[i], 0, sizeof(q->token_occupied_bytes[i][0]) * sketch_width);
        get_random_bytes(&q->sketch_perturbation[i], sizeof(q->sketch_perturbation[i]));
    }
}

static void ftbf_fill_flow_id(struct ftbf_flow_id *fid,
        struct sk_buff *skb, struct ftbf_sched_data *q)
{
    unsigned int i;
    for (i = 0; i < sketch_depth; ++i) {
        fid->flow_hash[i] = skb_get_hash_perturb(skb, &q->sketch_perturbation[i]);
    }
}

static void ftbf_update_sketch(u32 *hash, u64 **sketch, s64 count)
{
    unsigned int i = 0;
    u32 hashval = 0;
    for (i = 0; i < sketch_depth; ++i) {
        hashval = hash[i] % sketch_width;
        sketch[i][hashval] += count;
    }
}

static u64 ftbf_estimate_sketch(u32 *hash, u64 **sketch)
{
    unsigned int i = 0;
    u64 minval = U64_MAX;
    u32 hashval = 0;
    for (i = 0; i < sketch_depth; ++i) {
        hashval = hash[i] % sketch_width;
        minval = min(minval, sketch[i][hashval]);
    }
    return minval;
}

static u64 ftbf_calculate_token_threshold(struct ftbf_sched_data *q, u64 tokens)
{
    u64 threshold;
    threshold = (alpha_shift >= 0 ?
                (tokens >> alpha_shift) : (tokens << (-alpha_shift)));
    return min_t(u64, threshold, psched_l2t_ns(&q->rate, flow_burst_bytes));
}

/*
 * Enqueue a flow from the active queue
 */
static int ftbf_aq_enqueue(struct ftbf_flow_id *fid, struct ftbf_sched_data *q)
{
    struct active_flow_queue *aq = &q->active_q;
    if (aq->len >= MAX_QUEUE_DEPTH) {
        pr_err("Unexpected: active flow queue full.\n");
        return -1;
    }
    memcpy(&(aq->que[aq->tail]), fid, sizeof(struct ftbf_flow_id));
    aq->tail = (aq->tail + 1) % MAX_QUEUE_DEPTH;
    aq->len ++;
    return 0;
}

/*
 * Dequeue a flow from the active queue
 */
static void ftbf_aq_dequeue(struct ftbf_sched_data *q)
{
    u64 now = 0;
    struct active_flow_queue *aq = &q->active_q;
    s64 generate_num = 0;
    u64 occupied_tokens = 0;
    u64 alloc_len_ns = 0;
    u64 left_num = 0;
    now = ktime_get_ns();
    // Length of token allocated to each flow
    alloc_len_ns = psched_l2t_ns(&q->rate, token_alloc_bytes);
    // # of generated tokens (of length alloc_len_ns)
    generate_num = (now - q->aq_last_dequeue_time) / alloc_len_ns;
    left_num = generate_num;
    while (left_num > 0 && aq->len > 0) {
        struct ftbf_flow_id *fid = &aq->que[aq->head];
        occupied_tokens = ftbf_estimate_sketch(fid->flow_hash, q->token_occupied_bytes);
        if (occupied_tokens > token_alloc_bytes) {
            ftbf_update_sketch(fid->flow_hash,
                    q->token_occupied_bytes, -token_alloc_bytes);
            ftbf_aq_enqueue(fid, q);
        } else {
            ftbf_update_sketch(fid->flow_hash,
                    q->token_occupied_bytes, -occupied_tokens);
        }
        aq->head = (aq->head + 1) % MAX_QUEUE_DEPTH;
        aq->len --;
        left_num --;
    }
    if (aq->len == 0) {
        q->aq_last_dequeue_time = now;
    } else {
        q->aq_last_dequeue_time += generate_num * alloc_len_ns;
    }
}

static bool ftbf_peak_present(const struct ftbf_sched_data *q)
{
    return q->peak.rate_bytes_ps;
}

static int ftbf_check_before_enqueue(struct sk_buff *skb, struct ftbf_sched_data *q) {
    s64 now = 0;
    s64 toks = 0;
    u64 occupied_tokens = 0;
    u64 token_threshold = 0;
    u64 pkt_len_ns = 0;
    struct ftbf_flow_id fid;
    s64 ptoks = 0;
    unsigned int len = qdisc_pkt_len(skb);

    ftbf_aq_dequeue(q);

    now = ktime_get_ns();
    toks = min_t(s64, now - q->t_c, q->buffer);

    if (ftbf_peak_present(q)) {
        ptoks = toks + q->ptokens;
        if (ptoks > q->mtu)
            ptoks = q->mtu;
        ptoks -= (s64) psched_l2t_ns(&q->peak, len);
    }

    toks += q->tokens;
    if (toks > q->buffer)
        toks = q->buffer;

    ftbf_fill_flow_id(&fid, skb, q);
    occupied_tokens = ftbf_estimate_sketch(fid.flow_hash, q->token_occupied_bytes);
    occupied_tokens = psched_l2t_ns(&q->rate, (unsigned int) occupied_tokens);
    token_threshold = ftbf_calculate_token_threshold(q, (u64) toks);

    pkt_len_ns = psched_l2t_ns(&q->rate, len);

    if (occupied_tokens <= token_threshold && toks >= pkt_len_ns && ptoks >= 0) {
        // send packet
        if (occupied_tokens == 0) {
            ftbf_aq_enqueue(&fid, q);
        }
        ftbf_update_sketch(fid.flow_hash, q->token_occupied_bytes, len);
        #if FTBF_DEBUG == 1
            pr_info(
                ",%lld,+,%u,%pI4,%u,%pI4,%u,%llu,%llu\n",
                now,
                fid.flow_hash[0],
                &ip_hdr(skb)->saddr,
                ntohs(tcp_hdr(skb)->source),
                &ip_hdr(skb)->daddr,
                ntohs(tcp_hdr(skb)->dest),
                occupied_tokens,
                token_threshold
            );
        #endif
        q->t_c = now;
        q->tokens = toks - pkt_len_ns;
        return 0;
    }
#if FTBF_DEBUG == 1
    pr_info(
        ",%lld,d,%u,%pI4,%u,%pI4,%u,%llu,%llu\n",
        now,
        fid.flow_hash[0],
        &ip_hdr(skb)->saddr,
        ntohs(tcp_hdr(skb)->source),
        &ip_hdr(skb)->daddr,
        ntohs(tcp_hdr(skb)->dest),
        occupied_tokens,
        token_threshold
    );
#endif
    return -1;
}

/* Time to Length, convert time in ns to length in bytes
 * to determinate how many bytes can be sent in given time.
 */
static u64 psched_ns_t2l(const struct psched_ratecfg *r,
             u64 time_in_ns)
{
    /* The formula is :
     * len = (time_in_ns * r->rate_bytes_ps) / NSEC_PER_SEC
     */
    u64 len = time_in_ns * r->rate_bytes_ps;

    do_div(len, NSEC_PER_SEC);

    if (unlikely(r->linklayer == TC_LINKLAYER_ATM)) {
        do_div(len, 53);
        len = len * 48;
    }

    if (len > r->overhead)
        len -= r->overhead;
    else
        len = 0;

    return len;
}

/* GSO packet is too big, segment it so that ftbf can transmit
 * each segment in time
 */
static int ftbf_segment(struct sk_buff *skb, struct Qdisc *sch,
               struct sk_buff **to_free)
{
    struct ftbf_sched_data *q = qdisc_priv(sch);
    struct sk_buff *segs, *nskb;
    netdev_features_t features = netif_skb_features(skb);
    unsigned int len = 0, prev_len = qdisc_pkt_len(skb);
    int ret, nb;

    segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);

    if (IS_ERR_OR_NULL(segs))
        return qdisc_drop(skb, sch, to_free);

    nb = 0;
    while (segs) {
        nskb = segs->next;
        segs->next = NULL;
        qdisc_skb_cb(segs)->pkt_len = segs->len;
        len += segs->len;
        ret = qdisc_enqueue(segs, q->qdisc, to_free);
        if (ret != NET_XMIT_SUCCESS) {
            if (net_xmit_drop_count(ret))
                qdisc_qstats_drop(sch);
        } else {
            nb++;
        }
        segs = nskb;
    }
    sch->q.qlen += nb;
    if (nb > 1)
        qdisc_tree_reduce_backlog(sch, 1 - nb, prev_len - len);
    consume_skb(skb);
    return nb > 0 ? NET_XMIT_SUCCESS : NET_XMIT_DROP;
}

static int ftbf_enqueue(struct sk_buff *skb, struct Qdisc *sch,
               struct sk_buff **to_free)
{
    struct ftbf_sched_data *q = qdisc_priv(sch);
    int ret;

    if (ftbf_check_before_enqueue(skb, q) < 0) {
        // TODO: segmentation GSO packets
        return qdisc_drop(skb, sch, to_free);
    }

    if (qdisc_pkt_len(skb) > q->max_size) {
        if (skb_is_gso(skb) && skb_gso_mac_seglen(skb) <= q->max_size)
            return ftbf_segment(skb, sch, to_free);
        return qdisc_drop(skb, sch, to_free);
    }
    ret = qdisc_enqueue(skb, q->qdisc, to_free);
    if (ret != NET_XMIT_SUCCESS) {
        if (net_xmit_drop_count(ret))
            qdisc_qstats_drop(sch);
        return ret;
    }

    qdisc_qstats_backlog_inc(sch, skb);
    sch->q.qlen++;
    return NET_XMIT_SUCCESS;
}

static struct sk_buff *ftbf_dequeue(struct Qdisc *sch)
{
    struct ftbf_sched_data *q = qdisc_priv(sch);
    struct sk_buff *skb;

    skb = q->qdisc->ops->peek(q->qdisc);
    skb = qdisc_dequeue_peeked(q->qdisc);
    if (unlikely(!skb))
        return NULL;

    qdisc_qstats_backlog_dec(sch, skb);
    sch->q.qlen--;
    qdisc_bstats_update(sch, skb);

    return skb;
}

static void ftbf_reset(struct Qdisc *sch)
{
    struct ftbf_sched_data *q = qdisc_priv(sch);

    qdisc_reset(q->qdisc);
    sch->qstats.backlog = 0;
    sch->q.qlen = 0;
    q->t_c = ktime_get_ns();
    q->tokens = q->buffer;
    q->ptokens = q->mtu;
    qdisc_watchdog_cancel(&q->watchdog);

    ftbf_reset_sketch(q);
    ftbf_reset_active_queue(q);
}

static const struct nla_policy ftbf_policy[TCA_FTBF_MAX + 1] = {
    [TCA_FTBF_PARMS]    = { .len = sizeof(struct tc_ftbf_qopt) },
    [TCA_FTBF_RTAB]    = { .type = NLA_BINARY, .len = TC_RTAB_SIZE },
    [TCA_FTBF_PTAB]    = { .type = NLA_BINARY, .len = TC_RTAB_SIZE },
    [TCA_FTBF_RATE64]    = { .type = NLA_U64 },
    [TCA_FTBF_PRATE64]    = { .type = NLA_U64 },
    [TCA_FTBF_BURST] = { .type = NLA_U32 },
    [TCA_FTBF_PBURST] = { .type = NLA_U32 },
};

static int ftbf_change(struct Qdisc *sch, struct nlattr *opt)
{
    int err;
    struct ftbf_sched_data *q = qdisc_priv(sch);
    struct nlattr *tb[TCA_FTBF_MAX + 1];
    struct tc_ftbf_qopt *qopt;
    struct Qdisc *child = NULL;
    struct psched_ratecfg rate;
    struct psched_ratecfg peak;
    u64 max_size;
    s64 buffer, mtu;
    u64 rate64 = 0, prate64 = 0;

    err = nla_parse_nested(tb, TCA_FTBF_MAX, opt, ftbf_policy, NULL);
    if (err < 0)
        return err;

    err = -EINVAL;
    if (tb[TCA_FTBF_PARMS] == NULL)
        goto done;

    qopt = nla_data(tb[TCA_FTBF_PARMS]);
    if (qopt->rate.linklayer == TC_LINKLAYER_UNAWARE)
        qdisc_put_rtab(qdisc_get_rtab(&qopt->rate,
                          tb[TCA_FTBF_RTAB]));

    if (qopt->peakrate.linklayer == TC_LINKLAYER_UNAWARE)
            qdisc_put_rtab(qdisc_get_rtab(&qopt->peakrate,
                              tb[TCA_FTBF_PTAB]));

    buffer = min_t(u64, PSCHED_TICKS2NS(qopt->buffer), ~0U);
    mtu = min_t(u64, PSCHED_TICKS2NS(qopt->mtu), ~0U);

    if (tb[TCA_FTBF_RATE64])
        rate64 = nla_get_u64(tb[TCA_FTBF_RATE64]);
    psched_ratecfg_precompute(&rate, &qopt->rate, rate64);

    if (tb[TCA_FTBF_BURST]) {
        max_size = nla_get_u32(tb[TCA_FTBF_BURST]);
        buffer = psched_l2t_ns(&rate, max_size);
    } else {
        max_size = min_t(u64, psched_ns_t2l(&rate, buffer), ~0U);
    }

    if (qopt->peakrate.rate) {
        if (tb[TCA_FTBF_PRATE64])
            prate64 = nla_get_u64(tb[TCA_FTBF_PRATE64]);
        psched_ratecfg_precompute(&peak, &qopt->peakrate, prate64);
        if (peak.rate_bytes_ps <= rate.rate_bytes_ps) {
            pr_warn_ratelimited("sch_ftbf: peakrate %llu is lower than or equals to rate %llu !\n",
                    peak.rate_bytes_ps, rate.rate_bytes_ps);
            err = -EINVAL;
            goto done;
        }

        if (tb[TCA_FTBF_PBURST]) {
            u32 pburst = nla_get_u32(tb[TCA_FTBF_PBURST]);
            max_size = min_t(u32, max_size, pburst);
            mtu = psched_l2t_ns(&peak, pburst);
        } else {
            max_size = min_t(u64, max_size, psched_ns_t2l(&peak, mtu));
        }
    } else {
        memset(&peak, 0, sizeof(peak));
    }

    if (max_size < psched_mtu(qdisc_dev(sch)))
        pr_warn_ratelimited("sch_ftbf: burst %llu is lower than device %s mtu (%u) !\n",
                    max_size, qdisc_dev(sch)->name,
                    psched_mtu(qdisc_dev(sch)));

    if (!max_size) {
        err = -EINVAL;
        goto done;
    }

    if (q->qdisc != &noop_qdisc) {
        err = fifo_set_limit(q->qdisc, qopt->limit);
        if (err)
            goto done;
    } else if (qopt->limit > 0) {
        child = fifo_create_dflt(sch, &bfifo_qdisc_ops, qopt->limit);
        if (IS_ERR(child)) {
            err = PTR_ERR(child);
            goto done;
        }

        /* child is fifo, no need to check for noop_qdisc */
        qdisc_hash_add(child, true);
    }

    sch_tree_lock(sch);
    if (child) {
        qdisc_tree_reduce_backlog(q->qdisc, q->qdisc->q.qlen,
                      q->qdisc->qstats.backlog);
        qdisc_destroy(q->qdisc);
        q->qdisc = child;
    }
    q->limit = qopt->limit;
    if (tb[TCA_FTBF_PBURST])
        q->mtu = mtu;
    else
        q->mtu = PSCHED_TICKS2NS(qopt->mtu);
    q->max_size = max_size;
    if (tb[TCA_FTBF_BURST])
        q->buffer = buffer;
    else
        q->buffer = PSCHED_TICKS2NS(qopt->buffer);
    q->tokens = q->buffer;
    q->ptokens = q->mtu;

    memcpy(&q->rate, &rate, sizeof(struct psched_ratecfg));
    memcpy(&q->peak, &peak, sizeof(struct psched_ratecfg));

    sch_tree_unlock(sch);
    err = 0;
done:
    return err;
}

static int ftbf_init(struct Qdisc *sch, struct nlattr *opt)
{
    unsigned int i = 0;
    struct ftbf_sched_data *q = qdisc_priv(sch);

    qdisc_watchdog_init(&q->watchdog, sch);
    q->qdisc = &noop_qdisc;

    if (opt == NULL)
        return -EINVAL;

    q->t_c = ktime_get_ns();

    /* Init F-TBF parameters */
    if (sketch_depth > MAX_SKETCH_DEPTH) {
        pr_err("sketch_depth (%u) larger than the maximum value (%u). Set sketch_depth to %u.\n",
               sketch_depth, MAX_SKETCH_DEPTH, MAX_SKETCH_DEPTH);
        sketch_depth = MAX_SKETCH_DEPTH;
    }
    if (sketch_width > MAX_SKETCH_WIDTH) {
        pr_err("sketch_width (%u) larger than the maximum value (%u). Set sketch_width to %u.\n",
               sketch_width, MAX_SKETCH_WIDTH, MAX_SKETCH_WIDTH);
        sketch_width = MAX_SKETCH_WIDTH;
    }
    for (i = 0; i < sketch_depth; ++i) {
        q->token_occupied_bytes[i] = kcalloc(sketch_width, sizeof(u64), GFP_KERNEL);
        if (!q->token_occupied_bytes[i])
            return -ENOMEM;
    }

    ftbf_reset_sketch(q);
    ftbf_reset_active_queue(q);

    pr_info("init F-TBF.\n");

    return ftbf_change(sch, opt);
}

static void ftbf_destroy(struct Qdisc *sch)
{
    unsigned int i = 0;
    struct ftbf_sched_data *q = qdisc_priv(sch);

    qdisc_watchdog_cancel(&q->watchdog);
    qdisc_destroy(q->qdisc);

    for (i = 0; i < sketch_depth; ++i) {
        kfree(q->token_occupied_bytes[i]);
    }
    pr_info("destroy F-TBF.\n");
}

static int ftbf_dump(struct Qdisc *sch, struct sk_buff *skb)
{
    struct ftbf_sched_data *q = qdisc_priv(sch);
    struct nlattr *nest;
    struct tc_ftbf_qopt opt;

    sch->qstats.backlog = q->qdisc->qstats.backlog;
    nest = nla_nest_start(skb, TCA_OPTIONS);
    if (nest == NULL)
        goto nla_put_failure;

    opt.limit = q->limit;
    psched_ratecfg_getrate(&opt.rate, &q->rate);
    if (ftbf_peak_present(q))
        psched_ratecfg_getrate(&opt.peakrate, &q->peak);
    else
        memset(&opt.peakrate, 0, sizeof(opt.peakrate));
    opt.mtu = PSCHED_NS2TICKS(q->mtu);
    opt.buffer = PSCHED_NS2TICKS(q->buffer);
    if (nla_put(skb, TCA_FTBF_PARMS, sizeof(opt), &opt))
        goto nla_put_failure;
    if (q->rate.rate_bytes_ps >= (1ULL << 32) &&
        nla_put_u64_64bit(skb, TCA_FTBF_RATE64, q->rate.rate_bytes_ps,
                  TCA_FTBF_PAD))
        goto nla_put_failure;
    if (ftbf_peak_present(q) &&
        q->peak.rate_bytes_ps >= (1ULL << 32) &&
        nla_put_u64_64bit(skb, TCA_FTBF_PRATE64, q->peak.rate_bytes_ps,
                  TCA_FTBF_PAD))
        goto nla_put_failure;

    return nla_nest_end(skb, nest);

nla_put_failure:
    nla_nest_cancel(skb, nest);
    return -1;
}

static int ftbf_dump_class(struct Qdisc *sch, unsigned long cl,
              struct sk_buff *skb, struct tcmsg *tcm)
{
    struct ftbf_sched_data *q = qdisc_priv(sch);

    tcm->tcm_handle |= TC_H_MIN(1);
    tcm->tcm_info = q->qdisc->handle;

    return 0;
}

static int ftbf_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
             struct Qdisc **old)
{
    struct ftbf_sched_data *q = qdisc_priv(sch);

    if (new == NULL)
        new = &noop_qdisc;

    *old = qdisc_replace(sch, new, &q->qdisc);
    return 0;
}

static struct Qdisc *ftbf_leaf(struct Qdisc *sch, unsigned long arg)
{
    struct ftbf_sched_data *q = qdisc_priv(sch);
    return q->qdisc;
}

static unsigned long ftbf_find(struct Qdisc *sch, u32 classid)
{
    return 1;
}

static void ftbf_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
    if (!walker->stop) {
        if (walker->count >= walker->skip)
            if (walker->fn(sch, 1, walker) < 0) {
                walker->stop = 1;
                return;
            }
        walker->count++;
    }
}

static const struct Qdisc_class_ops ftbf_class_ops = {
    .graft        =    ftbf_graft,
    .leaf        =    ftbf_leaf,
    .find        =    ftbf_find,
    .walk        =    ftbf_walk,
    .dump        =    ftbf_dump_class,
};

static struct Qdisc_ops ftbf_qdisc_ops __read_mostly = {
    .next        =    NULL,
    .cl_ops        =    &ftbf_class_ops,
    .id        =    "tbf",
    .priv_size    =    sizeof(struct ftbf_sched_data),
    .enqueue    =    ftbf_enqueue,
    .dequeue    =    ftbf_dequeue,
    .peek        =    qdisc_peek_dequeued,
    .init        =    ftbf_init,
    .reset        =    ftbf_reset,
    .destroy    =    ftbf_destroy,
    .change        =    ftbf_change,
    .dump        =    ftbf_dump,
    .owner        =    THIS_MODULE,
};

static int __init ftbf_module_init(void)
{
    int ret;
    ret = register_qdisc(&ftbf_qdisc_ops);
    pr_info("init module ftbf.\n");
    return ret;
}

static void __exit ftbf_module_exit(void)
{
    unregister_qdisc(&ftbf_qdisc_ops);
    pr_info("exit module ftbf.\n");
}
module_init(ftbf_module_init)
module_exit(ftbf_module_exit)
MODULE_LICENSE("GPL");
