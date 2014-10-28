#ifndef	__unp_rtt_h
#define	__unp_rtt_h

struct rtt_info {
    int	        rtt_rtt;    /* most recent measured RTT, in msec */
    int	        rtt_srtt;   /* smoothed RTT estimator, in msec */
    int         rtt_rttvar; /* smoothed mean deviation, in msec */
    int         rtt_rto;    /* current RTO to use, in msec */
    uint32_t    rtt_base;   /* # sec since 1/1/1970 at start */
};

#define	RTT_RXTMIN      1000    /* min retransmit timeout value, in seconds */
#define	RTT_RXTMAX      3000    /* max retransmit timeout value, in seconds */
#define	RTT_MAXNREXMT 	12      /* max # times to retransmit */

/* function prototypes */

void    rtt_debug(struct rtt_info *);
void    rtt_init(struct rtt_info *);
int     rtt_start(struct rtt_info *);
void    rtt_stop(struct rtt_info *, uint32_t);
int     rtt_timeout(struct rtt_info *, uint32_t);
uint32_t    rtt_ts(struct rtt_info *);

/* can be set to nonzero for addl info */
extern int  rtt_d_flag;	

#endif	/* __unp_rtt_h */
