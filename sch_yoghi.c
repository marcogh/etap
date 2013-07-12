/*
 * net/sched/sch_yoghi.c Simple Delay-only queueing discipline.
 * 
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Author:	Marco Ghidinelli,
 *
 */
 
#include <linux/config.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/rtnetlink.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <net/pkt_sched.h>

/* #define YDEBUG = 0  */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marco Ghidinelli <marcogh@linux.it>");
MODULE_DESCRIPTION("JustForFun");

/*
typedef struct queuedata {
	struct timer_list wd_timer;
	struct Qdisc * parent;
	struct Qdisc * me;
	__u32 limitmap;
} queuedata;
*/

struct Qdata{
		struct timer_list wd_timer;
		struct Qdisc * fifoq;
		struct Qdisc * me;
		__u32 limit;
		__u32 timer;
		__u32 ack_max;
		int br, dupack, dupack_abs, smss;
};

struct yoghi_sched_data
{
	struct Qdisc *fifoq;

	struct tcf_proto *filter_list;

	int bands;

	/* __u32 limitmap[TCQ_YOGHI_BANDS]; */
	struct Qdisc *queues[TCQ_YOGHI_BANDS];
	/* struct Qdisc *callback[TCQ_YOGHI_BANDS*2]; */
	/* struct timer_list wd_timer[TCQ_YOGHI_BANDS]; */
	struct Qdata queuedata[TCQ_YOGHI_BANDS];
};

static void yoghi_start_timer(struct Qdata* data)
{
	/* struct yoghi_sched_data *q = qdisc_priv(data->parent); */ 
	int delay;
	/* delay = PSCHED_US2JIFFIE(30000); */
	delay = PSCHED_US2JIFFIE(data->timer);
	/* printk("yoghi_start_timer: %d\n",data->timer); */
	mod_timer(&data->wd_timer, jiffies+delay);
	/* mod_timer(&q->wd_timer[band], jiffies+delay); */
}

static void yoghi_get_br(struct sk_buff *skb, struct Qdata *currdata)
{
	struct tcphdr *tcp;
	unsigned int smss = 1448;
	__u32 usdelay;
	__u32 msdelay;
	__u32 ack_curr;
	signed int br = 0;

	if(skb->nh.iph->protocol != IPPROTO_TCP){
		printk(KERN_DEBUG "y_enq: mi aspettavo un pacchetto TCP!\n");
		br = 0;
	}else{
		tcp = (struct tcphdr *)((u32)skb->nh.iph + (skb->nh.iph->ihl*4));
		ack_curr = ntohl(tcp->ack_seq);

		if(tcp->syn || tcp->fin){
			if(tcp->syn)
				printk(KERN_DEBUG "y_enq: SYN received: "
						"init flow\n");
			else
				printk(KERN_DEBUG "y_enq: FIN received: "
						"clear flow\n");
			currdata->dupack = 0; 
			br=0;
			/* currdata->limit=1; */
			currdata->ack_max=ack_curr;
		}else{
#if 0
		printk(KERN_DEBUG "yoghi_enqueue: "
	 		"skb->nh.iph = 0x%x; "
			"skb->nh.iph->ihl*4 = 0x%x; "
			"tcphdr = 0x%x\n",
			(u32)skb->nh.iph,
			skb->nh.iph->ihl*4,
			(u32)tcp);
		printk(KERN_DEBUG "yoghi_enqueue: tcphdr = 0x%x, "
			"h.th = 0x%x\n",
			(u32)tcp,
			(u32)skb->nh.iph +
			(skb->nh.iph->ihl)*4);
		printk(KERN_DEBUG "yoghi_enqueue: tcp: ihl=%d "
			"src=%d dst=%d ack=%ud ack_seq=%ud\n",
			skb->nh.iph->ihl,
			ntohs(tcp->source),
			ntohs(tcp->dest),
			ntohl(tcp->seq),
			ntohl(tcp->ack_seq)); 
#endif

		/* printk(KERN_DEBUG "yoghi_enqueue:" 
					"ackcur=%u ackmax=%u br=%u\n",
					ack_curr, currdata->ack_max,
					ack_curr - currdata->ack_max); */
	
		if(ack_curr == currdata->ack_max){
			/* printk(KERN_DEBUG "ye:1 "); */
			br = smss;
			currdata->dupack++;
			currdata->dupack_abs++;
		}else if(ack_curr > (currdata->ack_max + currdata->dupack*smss)){
			/* 
			printk(KERN_DEBUG "ye:2 ");
			*/
			br = ack_curr
				- ((currdata->dupack)*smss)
				- currdata->ack_max;
			if( br < 0 )
				br = 0;
			currdata->dupack = 0;
		}else if(ack_curr > currdata->ack_max){
			/* printk(KERN_DEBUG "ye:3 "); */
			br = smss;
			currdata->dupack -= (ack_curr - currdata->ack_max )/smss -1;
		}

		msdelay = ( 8000 * (__u32)br );
		usdelay = msdelay/currdata->limit;
		usdelay = usdelay * 1000;

	/* printk(KERN_DEBUG "yoghi_enqueue: ack[max=%12u cur=%12u] br=%6u "
			"dupack=%d limit=%d delay=%d (ms) \n",
			currdata->ack_max, ack_curr, (__u32)br,
			currdata->dupack,
			currdata->limit, usdelay/1000); */
					
		currdata->ack_max = ack_curr;

		/* imposto il delay al pacchetto e incrocio le dita */
		currdata->timer = usdelay; 
		/* currdata->limit = 10000; */
		}
	}
}

void yoghi_watchdog(unsigned long arg)
{	
	struct sk_buff *skb;
	int ret;
	/* TODO lock */
	struct Qdata * qdata = (struct Qdata *)arg;

#ifdef YDEBUG
	/* printk("yoghi_watchdog: wake up queue lengh: %d\n",qdata->me->q.qlen); */
#endif	

	/* scaduto il timeout e la coda e' vuota, vuol dire che 
	 * la coda non deve essere piu' limitata */
	if(qdata->me->q.qlen == 0){
		qdata->me->flags &= ~TCQ_F_THROTTLED;
		return;
	}

	skb = (qdata->me->dequeue(qdata->me));

	yoghi_get_br(skb,qdata);
	
	if((ret = qdata->fifoq->ops->enqueue(skb,qdata->fifoq)) == NET_XMIT_SUCCESS){
		/* TODO aggiungere roba conteggio pacchetti */
#ifdef YDEBUG
		/* printk("yoghi_watchdog: requeue del pacchetto\n"); */
#endif
	}
	yoghi_start_timer(qdata);
	netif_schedule(qdata->me->dev);
#if 0
	
	struct Qdisc **sch_vect = (struct Qdisc **)arg;
	skb = (sch_vect[1])->dequeue(sch_vect[1]);
	if((ret = (sch_vect[0])->enqueue(skb,sch_vect[0])) == NET_XMIT_SUCCESS){
		/* TODO aggiungere roba conteggio pacchetti */
		printk("yoghi_watchdog: cambiato coda al pacchetto, "
				"chiamo netif_schedule()\n");
	}
	sch_vect[1]->flags &= ~TCQ_F_THROTTLED;
	/* yoghi_start_timer(sch_vect[1]); */
	printk("yoghi_watchdog: tolgo THROTTLED alla coda %x\n",(u32)sch_vect[1]);
	netif_schedule(sch_vect[0]->dev);
	/* TODO unlock */
#endif
};

/* yoghi_classify:
 * ritorna Qdisc* e cambia *qerr e *band. *band e' necessaria
 * per capire che watchdog attivare in yoghi_enqueue */
static struct Qdisc *
yoghi_classify(struct sk_buff *skb, struct Qdisc *sch, int *qerr, u32 *band)
{
	struct yoghi_sched_data *q = qdisc_priv(sch);
	struct tcf_result res;

	*qerr = NET_XMIT_DROP;
	*band = skb->priority;
#ifdef YDEBUG
	/* printk (KERN_DEBUG "yoghi_classify: pacchetto ricevuto\n"); */
#endif
	if (TC_H_MAJ(skb->priority) != sch->handle) {
#ifdef CONFIG_NET_CLS_ACT
		switch (tc_classify(skb, q->filter_list, &res)) {
		case TC_ACT_STOLEN:
		case TC_ACT_QUEUED:
			*qerr = NET_XMIT_SUCCESS;
		case TC_ACT_SHOT:
			return NULL;
		};

		if (!q->filter_list ) {
#else
		if (!q->filter_list || tc_classify(skb, q->filter_list, &res)) {
#endif
			/* TODO bah, qui non capisco proprio cosa vuole */
			if(TC_H_MAJ(*band)){
				printk(KERN_DEBUG "yoghi_classify: "
						"punto magico raggiunto :(\n");
				*band = 0;
			}
			*band = q->bands;
			return q->fifoq;
		}
		*band = res.classid;
	}
	*band = TC_H_MIN(*band) - 1;
	if (*band >= q->bands){
#ifdef YDEBUG
		printk(KERN_DEBUG "yoghi_classify: band > q->bands: %d > %d\n",*band,q->bands);
#endif
		*band = q->bands;
		return q->fifoq;
	}
	return q->queues[*band];
}

/* deve togliere solo dalla coda fifoq */
static struct sk_buff *
yoghi_dequeue(struct Qdisc* sch)
{
	struct yoghi_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	/* 
	struct Qdisc* qdisc;
	qdisc = q->fifoq;
	skb = qdisc->dequeue(qdisc);
	*/
	skb = q->fifoq->dequeue(q->fifoq);
	if(skb) {
		sch->q.qlen--;
		return skb;
	}
	return NULL;
}

static int
yoghi_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct yoghi_sched_data *q = qdisc_priv(sch);
	struct Qdisc *qdisc;
	/* struct tcphdr *tcp; */
	struct Qdata *currdata;
	/* unsigned int smss=1448; */
	/* __u32 usdelay;
	__u32 msdelay;
	__u32 ack_curr; 
	signed int br=0; */
	int ret;
	int band;
	int delay_timer=0;
#if 0
	/* struct iphdr *iph = skb->nh.iph; */

   	/* printk(KERN_INFO "yoghi_enqueue: TOS=0x%02X "
			"PROTOCOL: %d "
                    "TTL=%x SRC=%u.%u.%u.%u DST=%u.%u.%u.%u "
                    "ID=%u \n",
                    iph->tos, iph->protocol,
                    iph->ttl, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr),
                    ntohs(iph->id)
         ); */
	if(skb->nh.iph->protocol == IPPROTO_TCP){

		/* request_module("tcp_get_info"); */
		/* struct tcp_info ti;
		tcp_get_info(skb->sk,&ti); */
		/* printk(KERN_DEBUG "yoghi_enqueue: pacchetto skb->h.th riceuto: "
				"src=%d dst=%d\n",
				ntohs(skb->h.th->source),
				ntohs(skb->h.th->dest)); */
#endif
	qdisc = yoghi_classify(skb, sch, &ret, &band);
	
	currdata = &q->queuedata[band];

#ifdef CONFIG_NET_CLS_ACT
	if (qdisc == NULL) {
		if (ret == NET_XMIT_DROP)
			sch->qstats.drops++;
		kfree_skb(skb);
		return ret;
	}
#endif

	/* if(band < q->bands){
		yoghi_get_br(skb,currdata);
	}*/
	
#if 0
	if(band < q->bands){
		if(skb->nh.iph->protocol != IPPROTO_TCP){
			printk(KERN_DEBUG "y_enq: mi aspettavo un pacchetto TCP!\n");
		}else{
			tcp = (struct tcphdr *)((u32)skb->nh.iph +
					(skb->nh.iph->ihl*4));

			ack_curr = ntohl(tcp->ack_seq);

			if(tcp->syn || tcp->fin){
				if(tcp->syn)
					printk(KERN_DEBUG "y_enq: SYN received: init flow\n");
				else
					printk(KERN_DEBUG "y_enq: FIN received: clear flow\n");
				currdata->dupack = 0; 
				br=0;
				/* currdata->limit=1; */
				currdata->ack_max=ack_curr;
			}else{
#if 0
			printk(KERN_DEBUG "yoghi_enqueue: "
			 		"skb->nh.iph = 0x%x; "
					"skb->nh.iph->ihl*4 = 0x%x; "
					"tcphdr = 0x%x\n",
					(u32)skb->nh.iph,
					skb->nh.iph->ihl*4,
					(u32)tcp);
			printk(KERN_DEBUG "yoghi_enqueue: tcphdr = 0x%x, "
					"h.th = 0x%x\n",
					(u32)tcp,
					(u32)skb->nh.iph +
					(skb->nh.iph->ihl)*4);
			printk(KERN_DEBUG "yoghi_enqueue: tcp: ihl=%d "
					"src=%d dst=%d ack=%ud ack_seq=%ud\n",
					skb->nh.iph->ihl,
					ntohs(tcp->source),
					ntohs(tcp->dest),
					ntohl(tcp->seq),
					ntohl(tcp->ack_seq)); 
#endif

			/* printk(KERN_DEBUG "yoghi_enqueue:" 
					"ackcur=%u ackmax=%u br=%u\n",
					ack_curr, currdata->ack_max,
					ack_curr - currdata->ack_max); */
	
				if(ack_curr == currdata->ack_max){
					/* printk(KERN_DEBUG "ye:1 "); */
					br = smss;
					currdata->dupack++;
					currdata->dupack_abs++;
				}else if(ack_curr > (currdata->ack_max + currdata->dupack*smss)){
					/* 
					printk(KERN_DEBUG "ye:2 ");
					*/
					br = ack_curr
						- ((currdata->dupack)*smss)
						- currdata->ack_max;
					if( br < 0 )
						br = 0;
					currdata->dupack = 0;
				}else if(ack_curr > currdata->ack_max){
					/* printk(KERN_DEBUG "ye:3 "); */
					br = smss;
					currdata->dupack -= (ack_curr - currdata->ack_max )/smss -1;
				}

				msdelay = ( 8000 * (__u32)br );
				usdelay = msdelay/currdata->limit;
				usdelay = usdelay * 1000;

	/* 			printk(KERN_DEBUG "yoghi_enqueue: ack[max=%12u cur=%12u] br=%6u "
						"dupack=%d limit=%d delay=%d (ms) \n",
						currdata->ack_max, ack_curr, (__u32)br,
						currdata->dupack,
						currdata->limit, usdelay/1000); */
					
				currdata->ack_max = ack_curr;

				/* imposto il delay al pacchetto e incrocio le dita */
				currdata->timer = usdelay; 
				/* currdata->limit = 10000; */
			}
		}
	}
#endif

	if((band < q->bands) && (!(qdisc->flags & TCQ_F_THROTTLED))){
		/* se non e' la fifo e non e' trottolata: */
		qdisc->flags |= TCQ_F_THROTTLED;
		
		yoghi_get_br(skb,currdata);

		/* se la coda e' vuota metto il pacchetto direttamente 
		 * nella fifoq */
		if(qdisc->q.qlen == 0)
			qdisc = q->fifoq;

		delay_timer = 1;
	}
	if((ret = qdisc->enqueue(skb,qdisc)) == NET_XMIT_SUCCESS){
		sch->bstats.bytes += skb->len;
		sch->bstats.packets++;
		sch->q.qlen++;
	}else{
		/* TODO controlla se e' giusto questo sottto */
		sch->qstats.drops++;
	}
	
	if(delay_timer == 1)
		yoghi_start_timer(&q->queuedata[band]);
	return ret;
};

static int yoghi_change(struct Qdisc *sch, struct rtattr *opt)
{
	struct yoghi_sched_data *q = qdisc_priv(sch);
	struct tc_yoghi_qopt *qopt = RTA_DATA(opt);
	struct Qdisc *new;
	int i;

	if (opt->rta_len < RTA_LENGTH(sizeof(*qopt))){
		printk(KERN_DEBUG "dio merda\n");
		return -EINVAL;
	}
	if (qopt->bands > TCQ_YOGHI_BANDS){
		printk(KERN_DEBUG "dio frocio\n");
		return -EINVAL;
	}
	
	printk(KERN_DEBUG "yoghi_change: bands = %d\n",qopt->bands);
	
	q->bands = qopt->bands;	
	/* memcpy(q->limitmap, qopt->limitmap, (TC_PRIO_MAX+1)*sizeof(__u32)); */
	for(i=0 ; i<TCQ_YOGHI_BANDS ; i++){
		q->queuedata[i].limit = qopt->limitmap[i];
		q->queuedata[i].ack_max = 0;
		q->queuedata[i].br = 0;
		q->queuedata[i].dupack = 0;
		q->queuedata[i].dupack_abs = 0;
		q->queuedata[i].smss = 0;
	}

	/* crea la pfifo e la associa a fifoq */
	if ((new = qdisc_create_dflt(sch->dev, &pfifo_qdisc_ops)) == NULL)
		return -ENOBUFS;

	sch_tree_lock(sch);
	if((new = xchg(&q->fifoq,new)) != NULL) {
		/* trasha_via_la_oldqdisc(); */
		if (new != &noop_qdisc)
			/* TODO: capire se e' da distruggere o altro:
			 * potrebbe essere gia' a posto e pure con dentro 
			 * dei pacchetti.
			 */
			qdisc_destroy(new);
	}
	/* svuoto le classi > bands */
	for (i=qopt->bands; i<TCQ_YOGHI_BANDS; i++){
		new = xchg(&q->queues[i], new);
		if (new != &noop_qdisc)
			qdisc_destroy(new);
	}
	sch_tree_unlock(sch);
	
	/* TODO bands forse e' cannato????? */	
	for (i=0; i < qopt->bands; i++){
		printk (KERN_DEBUG
				"yoghi_change: init band %d: limit=%d\n",
				i,qopt->limitmap[i]);
		if((new = qdisc_create_dflt(sch->dev, &pfifo_qdisc_ops)) == NULL)
			return -ENOBUFS;
		sch_tree_lock(sch);
		new = xchg(&q->queues[i], new);
		if (new != &noop_qdisc)
			qdisc_destroy(new);
		sch_tree_unlock(sch);
	}

	/* TODO bands forse e' cannato????? */	
	for (i=0; i < qopt->bands; i++){
		q->queuedata[i].fifoq = q->fifoq;
		q->queuedata[i].me = q->queues[i];
	}

	
	for (i=0; i<TCQ_YOGHI_BANDS; i++){
		init_timer(&q->queuedata[i].wd_timer);
		q->queuedata[i].wd_timer.function = yoghi_watchdog;
		q->queuedata[i].wd_timer.data = (unsigned long)&q->queuedata[i];
#ifdef YDEBUG
		/* printk(KERN_DEBUG "yoghi_init: &q->queuedata[%d] = 0x%lx\n",
				i,(unsigned long)&q->queuedata[i]); */
#endif
	}
	
	return 0;
};

static void
yoghi_reset(struct Qdisc* sch)
{
	int i;
	struct yoghi_sched_data *q = qdisc_priv(sch);

	for (i=0; i<q->bands; i++)
		qdisc_reset(q->queues[i]);
	sch->q.qlen = 0;
}


static void
yoghi_destroy(struct Qdisc* sch)
{
	int i;
	struct yoghi_sched_data *q = qdisc_priv(sch);
	struct tcf_proto *tp;

	while ((tp = q->filter_list) != NULL) {
		q->filter_list = tp->next;
		tcf_destroy(tp);
	}

	for (i=0; i<q->bands; i++)
		qdisc_destroy(q->queues[i]);
	qdisc_destroy(q->fifoq);
}


static int yoghi_init(struct Qdisc *sch, struct rtattr *opt)
{
	struct yoghi_sched_data *q = qdisc_priv(sch);
	int i;
	
	printk(KERN_DEBUG "yoghi_init: here\n");
	
	q->fifoq = &noop_qdisc;
	
	for (i=0; i<TCQ_YOGHI_BANDS; i++)
		q->queues[i] = &noop_qdisc;
	
	if(opt != NULL){
		int err;

		if ((err = yoghi_change(sch, opt)) != 0)
			return err;
	}
#ifdef YDEBUG
	printk(KERN_DEBUG "Yoghi 0.9.8 Initialized\n");
	if(q != NULL)
		printk(KERN_DEBUG "yoghi_init: q = 0x%x\n",(u32)q);
#endif
	return 0;
};

/* bands: OK */
static struct Qdisc *
yoghi_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct yoghi_sched_data *q = qdisc_priv(sch);
	unsigned long band = arg - 1;

	if(band > q->bands)
		return NULL;
	if(band == q->bands)
		return q->fifoq;
	return q->queues[band];
}

/* bands: OK */
static unsigned long yoghi_get(struct Qdisc *sch, u32 classid)
{
	struct yoghi_sched_data *q = qdisc_priv(sch);
	u32 band  = TC_H_MIN(classid);
#ifdef YDEBUG
	printk(KERN_DEBUG "yoghi_get: classid = %d ; band = %d\n",classid,band);
#endif
	if (band -1 > q->bands)
		return 0; /* means not found */
	return band;
}


static unsigned long
yoghi_bind(struct Qdisc *sch, unsigned long parent, u32 classid)
{
	return yoghi_get(sch, classid);
}


static void yoghi_put(struct Qdisc *q, unsigned long cl)
{
	return;
}


/* bands: OK */
static void yoghi_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct yoghi_sched_data *q = qdisc_priv(sch);
	int i;

	if (arg->stop)
		return;
	/* differently from prio, we got <= in the test here */
	for (i = 0; i <= q->bands; i++) {
		if (arg->count < arg->skip) {
			arg->count++;
			continue;
		}
		/* qdisc, internal cl, *walker */
		if (arg->fn(sch, i+1, arg) < 0) {
			arg->stop = 1;
			break;
		}
		arg->count++;
	}
}

/* bands: OK */
static int yoghi_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		      struct Qdisc **old)
{
	struct yoghi_sched_data *q = qdisc_priv(sch);
	unsigned long band = arg - 1;

	if (band > q->bands)
		return -EINVAL;
	
	if (new == NULL)
		new = &noop_qdisc;

	sch_tree_lock(sch);
	if (band == q->bands){
		*old = q->fifoq;
		q->fifoq = new;
	}else{
		*old = q->queues[band];
		q->queues[band] = new;
	}
	sch->q.qlen -= (*old)->q.qlen;
	qdisc_reset(*old);
	sch_tree_unlock(sch);
	
	return 0;
}

static int yoghi_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct yoghi_sched_data *q = qdisc_priv(sch);
	unsigned char *b = skb->tail;
	int i;
	struct tc_yoghi_qopt opt;
	opt.bands = q->bands;
	/* memcpy(&opt.limitmap,q->limitmap,(TCQ_YOGHI_BANDS+1)*sizeof(__u32)); */
	for (i=0; i<TCQ_YOGHI_BANDS; i++)
		opt.limitmap[i] = q->queuedata[i].limit;
	RTA_PUT(skb, TCA_OPTIONS, sizeof(opt), &opt);
	return skb->len;
rtattr_failure:
	skb_trim(skb, b - skb->data);
	return -1;
}

static struct tcf_proto ** yoghi_find_tcf(struct Qdisc *sch, unsigned long cl)
{
	struct yoghi_sched_data *q = qdisc_priv(sch);

	if (cl){
		printk(KERN_DEBUG "yoghi_find_tc: Real Merda\n");
		return NULL;
	}
	return &q->filter_list;
}


static struct Qdisc_class_ops yoghi_class_ops = {
	.graft		=	yoghi_graft,
	.leaf		=	yoghi_leaf,
	.get		=	yoghi_get,
	.put		=	yoghi_put,
	.change		=	NULL,
	.delete		=	NULL,
	.walk		=	yoghi_walk,
	.tcf_chain	=	yoghi_find_tcf,
	.bind_tcf	=	yoghi_bind,
	.unbind_tcf	=	yoghi_put,
	.dump		=	NULL,
};

static struct Qdisc_ops yoghi_qdisc_ops = {
	.next		=	NULL,
	.cl_ops		=	&yoghi_class_ops,
	.id		=	"yoghi",
	.priv_size	=	sizeof(struct yoghi_sched_data),
	.enqueue	=	yoghi_enqueue,
	.dequeue	=	yoghi_dequeue,
	.requeue	=	NULL,
	.drop		=	NULL,		/* non la faccio */
	.init		=	yoghi_init,
	.reset		=	yoghi_reset,
	.destroy	=	yoghi_destroy,
	.change		=	yoghi_change,
	.dump		=	yoghi_dump,
	.owner		=	THIS_MODULE,
};

static int __init yoghi_module_init(void)
{
	printk(KERN_DEBUG "yoghi module loaded\n");
	return register_qdisc(&yoghi_qdisc_ops);
};

static void __exit yoghi_module_exit(void) 
{
	unregister_qdisc(&yoghi_qdisc_ops);
};

module_init(yoghi_module_init);
module_exit(yoghi_module_exit);
