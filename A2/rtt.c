#include "unp.h"
#include "unprtt.h"

/* debug flag; can be set by caller */
int rtt_d_flag = 1;

/*
 * Calculate the RTO value based on current estimators:
 *		smoothed RTT plus four times the deviation
 */
#define	RTT_RTOCALC(ptr) (((ptr)->rtt_srtt >> 3) + ((ptr)->rtt_rttvar))

static int
rtt_minmax(int rto) {
    if (rto < RTT_RXTMIN)
        rto = RTT_RXTMIN;
    else if (rto > RTT_RXTMAX)
        rto = RTT_RXTMAX;
    return(rto);
}

void
rtt_init(struct rtt_info *ptr) {
    struct timeval tv;

    /* # sec since 1/1/1970 at start */
    Gettimeofday(&tv, NULL);
    ptr->rtt_base = tv.tv_sec;

    ptr->rtt_rtt    = 0;
    ptr->rtt_srtt   = 0;
    ptr->rtt_rttvar = 750 << 2;
    ptr->rtt_rto = rtt_minmax(RTT_RTOCALC(ptr));

    fprintf(stderr, "Init RTT : ");
    rtt_debug(ptr);
    /* first RTO at (srtt >> 3 + (rttvar)) = 3 seconds */
}

/*
 * Return the current timestamp.
 * Our timestamps are 32-bit integers that count milliseconds since
 * rtt_init() was called.
 */

/* include rtt_ts */
uint32_t
rtt_ts(struct rtt_info *ptr) {
    uint32_t ts;
    struct timeval tv;

    Gettimeofday(&tv, NULL);
    ts = ((tv.tv_sec - ptr->rtt_base) * 1000) + (tv.tv_usec / 1000);
    return(ts);
}

int
rtt_start(struct rtt_info *ptr) {
    return ptr->rtt_rto;
    /* 4return value can be used as: alarm(rtt_start(&foo)) */
}
/* end rtt_ts */

/*
 * A response was received.
 * Stop the timer and update the appropriate values in the structure
 * based on this packet's RTT.  We calculate the RTT, then update the
 * estimators of the RTT and its mean deviation.
 * This function should be called right after turning off the
 * timer with alarm(0), or right after a timeout occurs.
 */

/* include rtt_stop */
void
rtt_stop(struct rtt_info *ptr, uint32_t lastTimeStamp) {
    int delta;

    /* measured RTT in seconds */
    ptr->rtt_rtt = rtt_ts(ptr) - lastTimeStamp;

    /*
     * Update our estimators of RTT and mean deviation of RTT.
     * See Jacobson's SIGCOMM '88 paper, Appendix A, for the details.
     * We use floating point here for simplicity.
     */

    // g = 1/8
    delta = ptr->rtt_rtt - (ptr->rtt_srtt >> 3); 
    ptr->rtt_srtt += delta;
    
    // |+/- delta|
    if (delta < 0)
        delta = -delta;
    
    // h = 1/4
    ptr->rtt_rttvar += delta - (ptr->rtt_rttvar >> 2);

    ptr->rtt_rto = rtt_minmax(RTT_RTOCALC(ptr));
    rtt_debug(ptr);
}
/* end rtt_stop */

/*
 * A timeout has occurred.
 * Return -1 if it's time to give up, else return 0.
 */

/* include rtt_timeout */
int
rtt_timeout(struct rtt_info *ptr, uint32_t retransmitCnt) {
    /* next RTO */
    ptr->rtt_rto = rtt_minmax(ptr->rtt_rto * 2);
    rtt_debug(ptr);

    if (retransmitCnt >= RTT_MAXNREXMT)
        return(-1);			/* time to give up for this packet */
    return(0);
}
/* end rtt_timeout */

/*
 * Print debugging information on stderr, if the "rtt_d_flag" is nonzero.
 */

void
rtt_debug(struct rtt_info *ptr) {
    if (rtt_d_flag == 0)
        return;

    fprintf(stderr, "rtt = %d, srtt = %d, rttvar = %d, rto = %d\n",
            ptr->rtt_rtt, ptr->rtt_srtt, ptr->rtt_rttvar, ptr->rtt_rto);
    fflush(stderr);
}

