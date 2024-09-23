// TODO handle error messages
// TODO physical channel insert zone length from mib - remove MAX_INSERT_ZONE_SIZE
// TODO handle mc frame service frame NOT having fecf and normal service HAVING fecf


#define IP_RECEIVE 1
// #define FILE_RECEIVE 1
// #define ASCII_FILE_RECEIVE 1
#define BINARY_FILE_RECEIVE 1

#define KLMTXDELAY 8
#define NEWMAKETFDFHEADER 1
#define MAX_IZ_LENGTH 258
#define FRAME_HEADER_LENGTH 7
#define TRUNCATED_FRAME_HEADER_LEN 4
#define DOPRINTFS 8
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h> // for vklmprintf
#include <map>
#include <semaphore.h>

#include "kcpq.cc" // circular packet queue - includes kpmutex for PMutex class
#include "kudprxtxclass.cc"
#include "kpthread.cc"

#include <string>
typedef std::string String;

struct timeval klmtv;


// cop directive frame len assumes a ONE-octet frame counter, dirid of < 256, dirtype of < 256, and dirqualifier of < 256

// cop directive types
enum cdt
{
    cdt_initiateAdServiceWithoutClcwCheck = 1,
    cdt_initiateAdServiceWithClcwCheck = 2,
    cdt_initiateAdServiceWithUnlock = 3,
    cdt_initiateAdServiceSetVr = 4,
    cdt_terminateAdService = 5,
    cdt_resumeAdService = 6,
    cdt_setVsToVs = 7,
    cdt_setFopSlidingWindowWidth = 8,
    cdt_setT1initial = 9,
    cdt_setTransmissionLimit = 10,
    cdt_setTimeoutType = 11,
    noCopInEffect = 0,
    CopOneInEffect = 1,
    CopPInEffect = 2
};

//#define TRANSMIT_WHAT_YOU_RECEIVE 1 // run rx, but do a tx from the notify indication

#define COP_DUMMY_CRC "frog"
#define NOTIFY_IND_POSITIVE_CONFIRM 0
#define NOTIFY_IND_NEGATIVE_CONFIRM 1
char *notificationString[2] = { (char *)"Positive Confirm",
    (char *)"Negative Confirm" };

#define TOTAL_VERIFICATION_STATUS_CODES 10
#define SDLS_ERROR_verificationStatusCode 111
char *verStatCodeStr[TOTAL_VERIFICATION_STATUS_CODES] = 
{ 
    (char *)"<NO ERRORS AT ALL!!!>",
    (char *)"<Invalid Sec Param 1>", 
    (char *)"<Invalid Sec Param 2>", 
    (char *)"<Invalid Sec Param 3>", 
    (char *)"<MAC Ver Failure!  4>", 
    (char *)"<MAC Ver Failure!  5>", 
    (char *)"<AntiReplay Seq Fl 6>",
    (char *)"<AntiReplay Seq Fl 7>", 
    (char *)"<Padding Error ... 8>",
    (char *)"<Padding Error ... 9>" 
}; // verification status code
#define TIMER_TIMEOUT_STUFF 1
#define PTFBITFIELDREWRITTEN 1
#define MAX_ISOCHRONOUS_DATA_LENGTH 256
#define MAX_MASTER_CHANNEL_IDS 1048576 /* 2^20 4-bit transfer frame version number + 16 bit spacecraft id */
// note MC_ID 786474 = c002a of USLP transfer frame verison number 12 and spacecraft id of 42*/
#define MAX_PHYSCHAN_STR_LENGTH 200
#define MAX_SPACECRAFT_IDS 65535
#define MAX_VCIDS 64
#define MAX_MAP_IDS 16
#define MAX_TRUNCATED_FRAME_TOTAL_LENGTH 256

#define MAX_OCF_LENGTH 4
// notice there are ONLY 2 pvns so far (reference 8) http://sanaregistry.org/r/packet_version_number/packet_version_number.html
#define OCFS_IN_QUEUE 100
#define MINIMUM_FRAME_HEADER_SIZE 7
#define TFDFS_IN_QUEUE 100
#define VC_FRAME_SERVICES_IN_QUEUE 10
#define MASTER_CHANNEL_FRAME_SERVICES_IN_QUEUE 10
#define MAX_TODO_Q_ENTRIES 1000

#define MAX_INSERT_ZONE_SIZE 65535
#define INSERT_ZONES_IN_QUEUE 10
#define FRAME_PRIMARY_HEADER_OCTETS 7

#define MAX_TFDF_HEADER_SIZE 4
#define MAX_PACKET_VERSION_NUMBERS 8
#define BIGGEST_POSSIBLE_POSITIVE_INTEGER 0x7fffffffffffffff
// #define FOREVER_IN_THE_FUTURE 0x7fffffffffffffff
#define FOREVER_IN_THE_FUTURE 2111111111
#define MAX_TRUNCATED_FRAME_LENGTH_OCTETS 8

#define MAX_FRAME_SIZE 					65536
#define MAX_SECURITY_HEADER_DATA	256
#define MAX_SECURITY_TRAILER_DATA	256
#define MAX_FECF_SIZE               4

#define ALL_ONES 0xffff
#define NO_VALUE -7

// integer values for possible construction rules
#define CR_000_SPANNING_DATA_UNITS          0
#define CR_001_MAPA_SDU_STARTS_MAY_END      1
#define CR_010_CONTINUING_MAPA_SDU_MAY_END  2
#define CR_011_OCTET_STREAM                 3
#define CR_100_UNFINISHED_SEGMENT_STARTS    4
#define CR_101_UNFINISHED_SEGMENT_CONTINUES 5
#define CR_110_CONTINUED_SEGMENT_ENDS       6
#define CR_111_SEGMENT_STARTS_AND_ENDS      7
// define the above values to be ORed in directly
#define OR_CR_000_SPANNING_DATA_UNITS          0x00
#define OR_CR_001_MAPA_SDU_STARTS_MAY_END      0x20
#define OR_CR_010_CONTINUING_MAPA_SDU_MAY_END  0x40
#define OR_CR_011_OCTET_STREAM                 0x60
#define OR_CR_100_UNFINISHED_SEGMENT_STARTS    0x80
#define OR_CR_101_UNFINISHED_SEGMENT_CONTINUES 0xa0
#define OR_CR_110_CONTINUED_SEGMENT_ENDS       0xc0
#define OR_CR_111_SEGMENT_STARTS_AND_ENDS      0xe0

sem_t frameEvery5s_sem;

union icu
{
    unsigned char c[sizeof(int)];
    int i;
} Uic;
union llcu
{
    unsigned char c[sizeof(long long)];
    long long ll;
} LLllc;

// allow for big-endian/little-endian definitions
// integer MSB NMSB NLSB LSB union character offset definitions

// uncomment the below to choose some other endianness than hardcoded

// hardcoded endianness below
#define I_LSB  0
#define I_NLSB 1
#define I_NNMSB 2
#define I_MSB  3
// integer LL_7O LL_60 LL_5O LL_40 LL_30 LL_20 LL_10 LL_0O union character offset where 0 is the least significant octet
#define LL_70 7
#define LL_60 6
#define LL_50 5
#define LL_40 4
#define LL_30 3
#define LL_20 2
#define LL_10 1
#define LL_00 0
// the above is what it is on a linux system

// arrays to allow different endiannesses
// lsb-to-msb offsets for endianedness
int ll_07lsbtomsb[8] = { 0, 1, 2, 3, 4, 5, 6, 7 }; // lsb is 0, msb is 7
int ll_07msbtolsb[8] = { 7, 6, 5, 4, 3, 2, 1, 0 }; // lsb is 7, msb is 0
int i_03lsbtomsb[4] = { 0, 1, 2, 3 };
int i_03msbtolsb[4] = { 3, 2, 1, 0 };
int *endianintegerlsbtomsb; // point to the right array based on endianness
int *endianlonglonglsbtomsb; // point to the right array based on endianness
bool constrRuleContainsFhpLvo[8] = { true,true,true,false,false,false,false,false }; // 4.1.4.2.4.2 - fhp/lvo only in 000,001,010. could do constrRule < 3 i guess...
const char *crstr[8] = { (const char *)"000",(const char *)"001",(const char *)"010",(const char *)"011",(const char *)"100",(const char *)"101",(const char *)"110",(const char *)"111" }; // this will not be in final product

// two new frames to compare with matt's bitwise frame construction/parsing
unsigned char fastbitTxFrame[MAX_FRAME_SIZE]; 
unsigned char fastbitRcvFrame[MAX_FRAME_SIZE];
// two new frames to compare with matt's bitwise frame construction/parsing
unsigned char klmReadableIdlePacket[] = "ENCAPSULATED-IDLE=PACKET_";
int global_MY_SPACECRAFT_ID = 42; // default to 42, but set by mibconfig

int klmglobalFrameSize = -1;
char klmglobalFrameType[22] ={""};
char klmReadFromThisFile[500];
long long globalUsTimeNow = 0; // microseconds time now
int startSecs = 0;
union charint
{
    int i;
    char c[sizeof ( int )];
} ;
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// new fastbit parse-TransferFrameHeader
int ptfVersion_id;
int ptfSpacecraftId;
int ptfDest_src;
int ptfVcid;
int ptfMapid;
int ptfEndOfTransferFrameHeader;
int ptfFramelen;
int ptfBypassFlag;
int ptfProtocolCommandControlFlag;
int ptfOcfFlag;
int ptfVcSeqCounterOctets;
long long ptfVcSequenceCount; // actual sequence count (can't be more octets than vcSeqCounterOctets)
// new fastbit parse-TransferFrameHeader
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

enum
{
    eTrue = 1,
    eFalse = 0,
    ePresent = 1,
    eAbsent = 0,
    eFixed = 1,
    eVariable = 0,
    eMAP_PACKET = 1,
    eMAPA_SDU = 2,
    eOCTET_STREAM = 3,
    eCOP = 4,
    eSequenceControlled = 0,
    eExpedited = 1,
    ePktErrRxdPktStartWithNonEmptyAssemblyBuf = 1, // error must be nonzero
    ePktErrRxdContinuationWithNoBeginSegment = 2,
    eMapaErrRxdStartingMapaWithNonEmptyAssemblyBuf = 3,
    eMapaErrRxdContinuingMapaWithEmptyAssemblyBuf = 4,
    eMapaErrRxdVarStartingMapaWithNonEmptyAssemblyBuf = 5,
    ePktErrRxdVarStartingPacketWithNonEmptyAssemblyBuf = 6,
    ePktErrRxdVarContinuingPacketWithEmptyAssemblyBuf = 7,
    eMapaErrRxdVarContinuingMapaWithEmptyAssemblyBuf = 8,
    ePktErrRxdVarEndingSegPacketWithEmptyAssemblyBuf = 9,
    eMapaErrRxdVarEndingSegMapaWithEmptyAssemblyBuf = 10,
    ePktErrRxdPktEndspanWithTooShortRxAssemblyBuf = 11,
    eMapaErrRxdVarConstRule111WithNonEmptyAssemblyBuf = 12,
    eDumpingCurrentRxAssemblyBufDueToRxdSdlsError = 13
};

PMutex kprMutex;
void klmprintf( const char* format, ... )
{
    va_list arglist;

    kprMutex.lock();
    va_start( arglist, format );
    vprintf( format, arglist );
    va_end( arglist );
    kprMutex.unlock();
}



const char *seedataSearchString = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789(),.:!=-_<>[]{};~";
void seeframe ( unsigned char * seebuf, int nbytes ) // bytes 0-8 are always hex for frame-counter-sort reasons
{
    for ( int i = 0 ; i < nbytes ; i ++ )
    {
        char c = seebuf[i];
        if ( i <= 8 ) // header and 2 length bytes always hex
        {
            printf ( "%02x ", c & 0xff );
        }
        else if ( c == '\0' ) // handle null before strchr (won't find null)
        {
            printf ( "%02x ", c & 0xff );
        }
        else if ( strchr(seedataSearchString,c) != NULL) 
        {
            printf ( "%2c ", c & 0xff );
        }
        else
        {
            printf ( "%02x ", c & 0xff );
        }
    }
    printf("\n");fflush(stdout);
}
void seedata ( unsigned char * seebuf, int nbytes ) // dump all data according to searchstring
{
    for ( int i = 0 ; i < nbytes ; i ++ )
    {
        char c = seebuf[i];
        if ( c == '\0' ) // handle null before strchr (won't find null)
        {
            printf ( "%02x ", c & 0xff );
        }
        else if ( strchr(seedataSearchString,c) != NULL) 
        {
            printf ( "%2c ", c & 0xff );
        }
        else
        {
            printf ( "%02x ", c & 0xff );
        }
    }
}
int parseTFDFheader( unsigned char *fp, int *constructionRules, int *UslpProtocolId, int *fhplvo )
{
    int retval = 1; // return index of 1st octet after header (value will be 1 or 3)
    //
    // construction rules
    //
    Uic.i = 0;
    Uic.c[endianintegerlsbtomsb[0]] = fp[0] & 0xe0; // might as well and out the lower 5 bits
    *constructionRules = Uic.i >> 5; // the shift and one-octet copy should guarantee that only 3 bits will be used to determine the construction rules
    //
    // UslpProtocolId
    //
    Uic.i = 0;
    Uic.c[endianintegerlsbtomsb[0]] = fp[0] & 0x1f; // guarantee that only 5 bits are considered to make the integer of upid
    *UslpProtocolId = Uic.i; // guarantee only 5 bits in this integer
    //
    // FHPLVO
    //
    *fhplvo = 65535; // default to biggest possible number
    if ( constrRuleContainsFhpLvo[*constructionRules] ) // if we are supposed to add 
    {
        retval = 3;
        Uic.i = 0;
        Uic.c[endianintegerlsbtomsb[1]] = fp[1];  // next to the LSB octet of 16-bit integer
        Uic.c[endianintegerlsbtomsb[0]] = fp[2]; 	// LSB of 16-bit integer
        *fhplvo = Uic.i;				// guarantee only 16 bits will be used
    }
    kprMutex.lock();printf("PARSE retval %d tfdf hdr constr %d upid %d LVO? %s fhplvo %d = <",retval, *constructionRules, *UslpProtocolId, constrRuleContainsFhpLvo[*constructionRules] ? "Y" : "N", *fhplvo);seedata(fp,retval);printf(">\n");fflush(stdout);kprMutex.unlock();
    return retval;
}
int makeTFDFheader( unsigned char *fp, int constructionRules, int UslpProtocolId, int fhplvo )
{
    int retval = 1; // return index of 1st octet after header (value will be 1 or 3)
    fp[0] = 0; // erase 1st octet of header
    //
    // construction rules
    //
    Uic.i = constructionRules << 5; // the shift and one-octet copy guarantees that only 3 bits will be copied to the header
    fp[0] |= Uic.c[endianintegerlsbtomsb[0]];
    //
    // UslpProtocolId
    //
    Uic.i = UslpProtocolId & 0x1f; // guarantee only 5 bits in this integer
    fp[0] |= Uic.c[endianintegerlsbtomsb[0]];
    //
    // FHPLVO
    //
    if ( constrRuleContainsFhpLvo[constructionRules] ) // if we are supposed to add 
    {
        retval = 3;
        Uic.i = fhplvo & 0xffff; // guarantee only 16 bits will be used
        fp[1] = Uic.c[endianintegerlsbtomsb[1]];   // next to the LSB octet of 16-bit integer
        fp[2] = Uic.c[endianintegerlsbtomsb[0]]; 	// LSB of 16-bit integer
    }
    kprMutex.lock();printf("make  retval %d tfdf hdr constr %d upid %d LVO? %s fhplvo %d = <",retval, constructionRules,UslpProtocolId,constrRuleContainsFhpLvo[constructionRules]?"Y":"N",fhplvo);seedata(fp,retval);printf(">\n");fflush(stdout);kprMutex.unlock();
    return retval;
}
int makeTransferFrameHeaderNoLen  // return length of header including frame counter octets; let buildParamFrameAddLen() build the rest of the frame and add the length to fp[4&5]
(
 unsigned char *fp, // pointer at octet 0 of the frame
 int version_id,
 int spacecraftId,
 int dest_src,
 int vcid,
 int mapid,
 int endOfTransferFrameHeader,
 int bypassFlag,
 int protocolCommandControlFlag,
 // reserve spares will not be passed in
 int ocfFlag,
 int vcSeqCounterOctets,
 long long vcSequenceCount // actual sequence count (can't be more octets than vcSeqCounterOctets)
 )
{

    memset(fp,0,FRAME_HEADER_LENGTH ); // memset to zero the frame header size (not counting vc sequence counter octets)

    // 
    // version id
    // 
    Uic.i = version_id << 4;
    fp[0] |= Uic.c[i_03lsbtomsb[0]];  // LSB
    kprMutex.lock();printf("result = vrsid %15d %15d ",version_id, Uic.i);seedata(fp,8);printf("\n");fflush(stdout);kprMutex.unlock();

    // 
    // 
    // spacecraft id
    // 

    Uic.i = spacecraftId << 4;
    fp[0] |= Uic.c[i_03lsbtomsb[2]]; // nnmsb
    fp[1] |= Uic.c[i_03lsbtomsb[1]]; // nlsb
    fp[2] |= Uic.c[i_03lsbtomsb[0]]; // lsb
    kprMutex.lock();printf("result = sc id %15d %15d ",spacecraftId, Uic.i);seedata(fp,8);printf("\n");fflush(stdout);kprMutex.unlock();

    // source destination bit
    // 
    if ( dest_src == 1) 
    {	
        Uic.i = 8; // hardcoded OR value shifted to set the correct bit
        fp[2] |= Uic.c[i_03lsbtomsb[0]]; // lsb - NO NEED TO OR IN A ZERO
    }
    kprMutex.lock();printf("result = srcdst%15d %15d ",dest_src,Uic.i);seedata(fp,8);printf("\n");fflush(stdout);kprMutex.unlock();

    // 
    // VCID (6 bits)
    // 

    Uic.i = vcid << 5;
    fp[2] |= Uic.c[i_03lsbtomsb[1]]; // next to lsb
    fp[3] |= Uic.c[i_03lsbtomsb[0]]; // lsb
    kprMutex.lock();printf("result = VCID  %15d %15d ",vcid, Uic.i);seedata(fp,8);printf("\n");fflush(stdout);kprMutex.unlock();

    // 
    // MAPID (4 bits)
    // 
    Uic.i = mapid << 1;
    fp[3] |= Uic.c[i_03lsbtomsb[0]]; // lsb
    kprMutex.lock();printf("result = MAPID %15d %15d ",mapid, Uic.i);seedata(fp,8);printf("\n");fflush(stdout);kprMutex.unlock();

    // 
    // end of transfer frame header flag
    // 
    if ( endOfTransferFrameHeader == 1 ) 
    {
        Uic.i = 1; // hardcoded OR value in right spot to set the correct bit
        fp[3] |= Uic.c[i_03lsbtomsb[0]]; // lsb - NO NEED TO OR IN A ZERO
        kprMutex.lock();printf("result = eotfh %15d %15d ",endOfTransferFrameHeader, Uic.i);seedata(fp,8);printf("\n");fflush(stdout);kprMutex.unlock();
        return TRUNCATED_FRAME_HEADER_LEN; // if we ARE ORing in an endOfTransferFrameHeader then it's a truncated frame and we don't need to OR in anything else
    }

    // 
    // frame length (16 bits) comes here in frame but figure at the END when you have all your other fields info
    // 

    // 
    // bypass flag
    // 
    if ( bypassFlag == 1 ) 
    {
        Uic.i = 128; // hardcoded OR value shifted to set the correct bit
        fp[6] |= Uic.c[i_03lsbtomsb[0]]; // lsb - NO NEED TO OR IN A ZERO
    }
    kprMutex.lock();printf("result = bypas %15d %15d ",bypassFlag, Uic.i);seedata(fp,8);printf("\n");fflush(stdout);kprMutex.unlock();


    // 
    // protocolControlCommand bit (1 bit)
    // 
    if ( protocolCommandControlFlag == 1 )
    {
        Uic.i = 64; // hardcoded OR value shifted to set the correct bit
        fp[6] |= Uic.c[i_03lsbtomsb[0]]; // lsb - NO NEED TO OR IN A ZERO 
    }
    kprMutex.lock();printf("result = pccFlg%15d %15d ",protocolCommandControlFlag, Uic.i);seedata(fp,8);printf("\n");fflush(stdout);kprMutex.unlock();

    // 2 bits reserve spare (already set to 0 by the memset above)

    // 
    // ocfFlag bit (1 bit)
    // 
    if ( ocfFlag == 1 ) 
    {
        Uic.i = 8; // hardcoded OR value shifted to set the correct bit
        fp[6] |= Uic.c[i_03lsbtomsb[0]]; //lsb - NO NEED TO OR IN A ZERO
    }
    kprMutex.lock();printf("result = ocfFlg%15d %15d ",ocfFlag, Uic.i);seedata(fp,8);printf("\n");fflush(stdout);kprMutex.unlock();


    // 
    // vc sequence counter Octets(3 bits)
    // 
    Uic.i = vcSeqCounterOctets & 0x7; // no shifting - 3 bits' worth
    fp[6] |= Uic.c[i_03lsbtomsb[0]]; // lsb
    kprMutex.lock();printf("result = vcSqO %15d %15d ",vcSeqCounterOctets, Uic.i);seedata(fp,8);printf("\n");fflush(stdout);kprMutex.unlock();

    // 
    // assign vc frame counter based on the number of vc counter octets
    // 
    LLllc.ll = 0ll; // assign value to long long
    LLllc.ll = vcSequenceCount; // assign value to long long
    for ( int i = 0 ; i < vcSeqCounterOctets ; i ++ )
    {
        // 
        // copy sequence counter octets (total of vcSeqCounterOctets octets) !!!! from MSB to LSB !!! into frame starting after the frame header
        // 
        // if 3 octets, get 2,1,0 ; if 2 octets get 1,0 if 7 octets get 6,5,4,3,2,1,0 where 0 is lsb and endianlonglonglsbtomsb[] is the sequence of LSB to MSB based on endian-ness
        fp[FRAME_HEADER_LENGTH + i] = LLllc.c[endianlonglonglsbtomsb[(vcSeqCounterOctets - 1) - i]]; 
    }
    kprMutex.lock();printf("result = COUNT %15lld %15lld ",vcSequenceCount, LLllc.ll);seedata(fp,8);printf("\n");fflush(stdout);kprMutex.unlock();

    /*
    // 
    // frame length (16 bits)
    // 
    Uic.i = framelen; // no shifting - 16 bits' worth
    fp[4] = Uic.c[i_03lsbtomsb[1]]; // next to lsb
    fp[5] = Uic.c[i_03lsbtomsb[0]]; // lsb
    kprMutex.lock();printf("result = frmlen%15d %15d ",framelen, Uic.i);seedata(fp,8);printf("\n");fflush(stdout);kprMutex.unlock();
    */

    // return 0-referenced octet in frame to start adding data 
    return FRAME_HEADER_LENGTH + vcSeqCounterOctets;
}
int fromstartsecs(void)
{
    // return (((int)(globalUsTimeNow / 1000000ll)) - startSecs);	
    return (((int)(globalUsTimeNow)) );	
}
// fills an ehs-encapsulated-idle packet (length 1 to 65536)
void idleFillHere ( unsigned char * copyToHere, int thisManyBytes , unsigned char *OIDdata )
{
    int fillThisMany = 0;
    klmprintf("idleFillHere fill thismanybytes %d\n",thisManyBytes );fflush(stdout);

    charint kcharint;
    kcharint.i = thisManyBytes;

    if ( thisManyBytes <= 0 ) // 0
    {
        return; // nothing to do
    }
    else if ( thisManyBytes < 2 ) // 1
    {
        *copyToHere++ = 0xE0; // 0 length bytes - one-byte idle packet
        fillThisMany = 0;
    }
    else if ( thisManyBytes < 256 )
    {
        *copyToHere++ = 0xE1; // one length byte
        *copyToHere++ = kcharint.c[0]; //  lsb
        fillThisMany = thisManyBytes - 2;
    }
    else if ( thisManyBytes < 65536 )
    {
        *copyToHere++ = 0xE2; // two length bytes
        *copyToHere++ = kcharint.c[1];  //  msb
        *copyToHere++ = kcharint.c[0];  //  lsb
        fillThisMany = thisManyBytes - 3;
    }
    // now that you have an idle header, fill the rest with idle DATA 
    // below for() loop is dummy data. 
    for ( int oidIdx = 0; fillThisMany > 0 ; ) // skip header
    {
        *copyToHere++ = OIDdata[oidIdx++];
        fillThisMany--; // one less octet
    }
    // klmprintf("3 endianintegerlsbtomsb %p i_03lsbtomsb %p\n",endianintegerlsbtomsb,i_03lsbtomsb);fflush(stdout);
}
bool isEncapsulatedIdlePacket(unsigned char *startOfBuf, int offsetOfFirstByteOfPacket, int octetsRemainingInTfdfIncludingFirstByteOfPacket)
{
    //
    // assume that the idle packet is the LAST THING in the tfdf (if bytes exist in tfdf AFTER encapsulated idle packet, this wasn't an encapsulated idle packet)
    // assume that the idle packet is the LAST THING in the tfdf (if bytes exist in tfdf AFTER encapsulated idle packet, this wasn't an encapsulated idle packet)
    // assume that the idle packet is the LAST THING in the tfdf (if bytes exist in tfdf AFTER encapsulated idle packet, this wasn't an encapsulated idle packet)
    //
    //
    unsigned char *firstByteOfPacket = &startOfBuf[offsetOfFirstByteOfPacket];
    bool retval = false;
    int epktlen = 0; 
    if ( *firstByteOfPacket == ( unsigned char ) 0xE0) // this is only octet in idle packet
    {
        epktlen = 1;
    }
    else if ( *firstByteOfPacket == ( unsigned char ) 0xE1) // one-octet length
    {
        epktlen = (int)(firstByteOfPacket[1]); // include header byte plus this byte in length
    }
    else if ( *firstByteOfPacket == ( unsigned char ) 0xE2) // 
    {
        epktlen = (int)(firstByteOfPacket[1]); // byte after header
        epktlen *= 256;
        epktlen += (int)(firstByteOfPacket[2]); // byte after header
    }
    // 
    // encapsulated idle packets can have four-octet lengths if started with 0xe3, but that would be longer than USLP frames can hold as idle packets. so it's not checked here.
    // 
    if ( octetsRemainingInTfdfIncludingFirstByteOfPacket == epktlen )
    {
        retval = true;
    }
    klmprintf("isEncapsulatedIdlePacket offset %d epktlen %d orib %d %s\n",offsetOfFirstByteOfPacket, epktlen, octetsRemainingInTfdfIncludingFirstByteOfPacket,retval?"IS  encap":"not encap");fflush(stdout);
    return retval;
}
int getPacketLength ( unsigned char * cp, int octetsAvailable )
{
    // get the length of this packet
    // for now i handle only 2: ccsds and encapsulated idle packets.
    charint kcharint;
    kcharint.i = 0; // init to 0 so bytes can be OR'd in
    //
    //
    // encapsulated idle packet
    //
    //
    if ( ( ( *cp & 0xF3 ) & 0xff ) == 0xE0 ) // always at least ONE octet available - if starts with 0xE? it's an encapsulated idle packet
    {
        kcharint.i = 1;
    }
    else if ( octetsAvailable >= 2 && ( ( *cp & 0xF3 ) & 0xff ) == 0xE1 ) // one octet length
    {
        kcharint.c[0] = * ( cp + 1 ); // length octet is after header byte and has total length
    }
    else if ( octetsAvailable >= 4 && ( ( *cp & 0xF3 ) & 0xff ) == 0xE2 ) // one character length
    {
        // for pkt length 2 skip user-defined field and protocol id extension in octet [1] (starting at [0])
        kcharint.c[1] = * ( cp + 2 ); // length octets start the byte after the byte after the header byte and have the total length
        kcharint.c[0] = * ( cp + 3 ); // length octets start the byte after the byte after the header byte and have the total length
    }
    //
    //
    // ccsds packet
    //
    //
    else if ( octetsAvailable >= 6 ) // it's a ccsds packet
    {
        kcharint.c[1] = * ( cp + 4 );
        kcharint.c[0] = * ( cp + 5 ); // ccsds length in octet 4&5 from 0; length does not include primary header and is minus-one
        kcharint.i += 6 + 1; // add header octets (length does not include header octets), and length is "minus one" so add one
    }
    else  // there weren't enough octets for packet length
    {
        kcharint.i = -1; // say you couldn't get the packet length
    }
    //
    // if there were enough octets to get the packet length, return it; else return BIGGEST_POSSIBLE_POSITIVE_INTEGER
    //
    return kcharint.i; // if negative i couldn't GET the packet length (packet split in the middle of the length)
}
// receive a pointer to the first octet in the frame after the VC counter octets
int parseFrameFields(unsigned char *fp, int offset,  // output frame and offset of first octet past frame header and vc frame counter to start adding the rest of the frame to
        bool izflag, int izlen, unsigned char *izdata,  // whether and what iz to add
        bool schdrflag, int schdrlen, unsigned char *schdrdata,  // whether and what security header to add
        int tfdflen, unsigned char *tfdfdata, bool isOidFrame, // what transfer frame data field (including TFDF header) to add
        bool sctrlrflag, int sctrlrlen, unsigned char *sctrlrdata,  // whether and what security trailer to add
        bool ocfflag, int ocflen, unsigned char *ocfdata,  // whether and what ocf data to add
        bool fecfflag, int fecflen, unsigned char *fecfdata) // whether and what fecf data to add
{
    // <..frame..hdr......> <Vctr> <..iz....>.<schdr.> <--------------------TFDF with header-------------------------------------->|  <...securityTrailer..>..<ocf.....>..<..fecf..>
    // c0 02 a0 00 00  9 0a 00 03  {  i  z  }  :  h  ; 03 00 0b  R  I  G  H  T  A  B  L  E  0  3 00  U  N  C 00 0d  O  P  Y  R  I  G  [  -  t  r  a  l  ~  ]  <  o  c  >  (  f  x  ) 
    //
    // start adding stuff to frame at fp[offset]
    //
    // if add iz
    if ( izlen > 0 && izflag ) // usually m_map_PHYSCHANptr->m_pc_Transfer_Frame_Type == eFixed && m_map_PHYSCHANptr->m_Presence_of_Isochronous_Insert_Zone == ePresent ) // if add iz, add iz ( // if variable PC frame type, IZ is forbidden (as per ed greenberg email, 2017/05/16))
    {
        memcpy(izdata, &fp[offset], izlen);
        offset += izlen;
    }
    // if add security header
    if ( schdrlen > 0 && schdrflag ) // usually m_myVcidParent->m_PresenceOfSpaceDataLinkSecurityHeader == ePresent )
    {
        memcpy(schdrdata, &fp[offset], schdrlen);
        offset += schdrlen;
    }
    // TFDF (including header) (for oid frames this will be framelen-frameheaderlen-vcCounterlen-izlen-ocflen)
    if ( tfdflen > 0 )
    {
        if ( !isOidFrame ) // only copy data if it's not an OID frame
        {
            memcpy(tfdfdata, &fp[offset], tfdflen);
        }
        offset += tfdflen; // still gotta move the pointer
    }
    // if add sctrlr
    if ( sctrlrlen > 0 && sctrlrflag ) //usually m_myVcidParent->m_PresenceOfSpaceDataLinkSecurityTrailer == ePresent)
    {
        memcpy(sctrlrdata, &fp[offset],  sctrlrlen);
        offset += sctrlrlen;
    }
    // if add ocf (verify that this handles OCF countdown)
    klmprintf("PFF ocf DATA ocfflag = %s from offset %d len %d\n",ocfflag?"true":"false",offset,ocflen);fflush(stdout);
    if ( ocflen > 0 && ocfflag ) // usually m_myVcidParent->m_vc_include_OCF
    {
        memcpy(ocfdata,  &fp[offset], ocflen);
        offset += ocflen;
    }
    // fecf
    if ( fecflen > 0 && fecfflag ) // usually m_map_PHYSCHANptr->m_Presence_of_Frame_Error_Control == ePresent )
    {
        memcpy(fecfdata, &fp[offset], fecflen);
        offset += fecflen;
    }
    /*
       Uic.i = offset - 1; // no shifting - 16 bits' worth
       fp[4] = Uic.c[i_03lsbtomsb[1]]; // next to lsb
       fp[5] = Uic.c[i_03lsbtomsb[0]]; // lsb
       kprMutex.lock();printf("bpfal  = frmlen%15d %15d ",offset, Uic.i);seedata(fp,offset);printf("\n");fflush(stdout);kprMutex.unlock();
       */
    return offset;
}
int buildParamFrameAddLen(unsigned char *fp, int offset,  // output frame and offset of first octet past frame header and vc frame counter to start adding the rest of the frame to
        bool izflag, int izlen, unsigned char *izdata,  // whether and what iz to add
        bool schdrflag, int schdrlen, unsigned char *schdrdata,  // whether and what security header to add
        int tfdflen, unsigned char *tfdfdata,  // what transfer frame data field (including TFDF header) to add
        bool sctrlrflag, int sctrlrlen, unsigned char *sctrlrdata,  // whether and what security trailer to add
        int ocfflag, int ocflen, unsigned char *ocfdata,  // whether and what ocf data to add
        bool fecfflag, int fecflen, unsigned char *fecfdata) // whether and what fecf data to add
{
    // <..frame..hdr......> <Vctr> <..iz....>.<schdr.> <--------------------TFDF with header-------------------------------------->|  <...securityTrailer..>..<ocf.....>..<..fecf..>
    // c0 02 a0 00 00  9 0a 00 03  {  i  z  }  :  h  ; 03 00 0b  R  I  G  H  T  A  B  L  E  0  3 00  U  N  C 00 0d  O  P  Y  R  I  G  [  -  t  r  a  l  ~  ]  <  o  c  >  (  f  x  ) 
    //
    // start adding stuff to frame at fp[offset]
    //
    // if add iz
    if ( izlen > 0 && izflag ) // usually m_map_PHYSCHANptr->m_pc_Transfer_Frame_Type == eFixed && m_map_PHYSCHANptr->m_Presence_of_Isochronous_Insert_Zone == ePresent ) // if add iz, add iz ( // if variable PC frame type, IZ is forbidden (as per ed greenberg email, 2017/05/16))
    {
        memcpy(&fp[offset],izdata, izlen);
        offset += izlen;
    }
    // if add security header
    if ( schdrlen > 0 && schdrflag ) // usually m_myVcidParent->m_PresenceOfSpaceDataLinkSecurityHeader == ePresent )
    {
        memcpy(&fp[offset],schdrdata, schdrlen);
        offset += schdrlen;
    }
    // TFDF (including header)
    if ( tfdflen > 0 )
    {
        memcpy(&fp[offset],tfdfdata, tfdflen);
        offset += tfdflen;
    }
    // if add sctrlr
    if ( sctrlrlen > 0 && sctrlrflag ) //usually m_myVcidParent->m_PresenceOfSpaceDataLinkSecurityTrailer == ePresent)
    {
        memcpy(&fp[offset], sctrlrdata, sctrlrlen);
        offset += sctrlrlen;
    }
    // if add ocf (verify that this handles OCF countdown)
    if ( ocflen > 0 && ocfflag == eTrue ) // usually m_myVcidParent->m_vc_include_OCF // TODO - does this handle countdown
    {
        memcpy(&fp[offset],ocfdata, ocflen);
        offset += ocflen;
    }
    // fecf
    if ( fecflen > 0 && fecfflag ) // usually m_map_PHYSCHANptr->m_Presence_of_Frame_Error_Control == ePresent )
    {
        memcpy(&fp[offset],fecfdata, fecflen);
        offset += fecflen;
    }
    // 
    // frame length (16 bits)
    // 
    Uic.i = offset - 1; // no shifting - 16 bits' worth
    fp[4] = Uic.c[i_03lsbtomsb[1]]; // next to lsb
    fp[5] = Uic.c[i_03lsbtomsb[0]]; // lsb
    kprMutex.lock();printf("bpfal  = frmlen%15d %15d ",offset, Uic.i);seedata(fp,offset);printf("\n");fflush(stdout);kprMutex.unlock();
    return offset;
}
class gmapid
{
    public:
        String PHYSCHAN;
        int TFVN;
        int SCID;
        int VCID;
        int MAPID;
        gmapid() {}
        void set ( String lPHYSCHAN, int lTFVN, int lSCID, int lVCID, int lMAPID )
        {
            PHYSCHAN = lPHYSCHAN;
            TFVN = lTFVN;
            SCID = lSCID;
            VCID = lVCID;
            MAPID = lMAPID;
        }
};
class gvcid
{
    public:
        String PHYSCHAN;
        int TFVN;
        int SCID;
        int VCID;
        gvcid() {}
        void set ( String lPHYSCHAN, int lTFVN, int lSCID, int lVCID )
        {
            PHYSCHAN = lPHYSCHAN;
            TFVN = lTFVN;
            SCID = lSCID;
            VCID = lVCID;
        }
        void setVcid ( int lVCID ) // only setting VCID (used by mc ocf delivery to deliver OCF to all VCIDs that want an ocf
        {
            VCID = lVCID;
        }
};
class gmasterChannelId
{
    public:
        String PHYSCHAN;
        int TFVN;
        int SCID;
        gmasterChannelId() {}
        void set ( String lPHYSCHAN, int lTFVN, int lSCID )
        {
            PHYSCHAN = lPHYSCHAN;
            TFVN = lTFVN;
            SCID = lSCID;
        }
};
typedef gmapid gmapid_t;
typedef gvcid gvcid_t;
void kerror ( const char * error,int value )
{
    klmprintf ( "%s - %d\n",error,value );
    fflush ( stdout );
}
String param[10]; // for parsing config params
int global_Require_Incomplete_MAPA_Delivery_To_User_At_Receiving_End = eTrue;
struct tde
{
    int mcid;
    int vcid;
    int mapid;
    int pvn;
    int what;
    int when;
    unsigned char physchanstr[MAX_PHYSCHAN_STR_LENGTH];
} toDoEntry;
class packetinfo
{
    public:
        bool m_Valid_Packet_Version_Numbers[MAX_PACKET_VERSION_NUMBERS];
        int m_orderedValidPvns[MAX_PACKET_VERSION_NUMBERS];
        int m_Maximum_Packet_Length;
        bool m_Require_Incomplete_Packet_Delivery_To_User_At_Receiving_End;
        int m_minimumValidPvn; // multiplexed pvns all funnel to this pvn
        int m_numberOfValidPvns; // total number of valid pvns to try
        //
        // constr
        //
        packetinfo()
        {
            for ( int i=0; i < MAX_PACKET_VERSION_NUMBERS; i++ )
            {
                m_Valid_Packet_Version_Numbers[i] = false;
            }
            m_minimumValidPvn = -1; // assign a sure core-dump to mandate being specified in the mib
        }
        void constructOrderedValidPvns(void)
        {
            m_numberOfValidPvns = 0;
            for ( int i=0; i < MAX_PACKET_VERSION_NUMBERS; i++ )
            {
                m_orderedValidPvns[i] = -1; // preset to illegal 
                if ( m_Valid_Packet_Version_Numbers[i] ) // this one's valid
                {
                    m_orderedValidPvns[m_numberOfValidPvns++] = i; // add it to the list
                }
            }
        }
        int getIndexOfThisOrderedPvn(int pvn)
        {
            int retval = -1; // invalid index
            for ( int i=0; i < MAX_PACKET_VERSION_NUMBERS; i++ )
            {
                if ( m_orderedValidPvns[i] == pvn)
                {
                    retval = i;
                }
            }
            return retval;	
        }
} packetInfoMib;

class kphysicalChannel;
class kmasterChannel;
class kvcid;
class kmapid
{
    public:
        char m_parentstr[100];
        char *mapktree(void);
        unsigned char *m_map_pcOidData; // propagate PC oid info
        int m_completePacket; // used as packet quality indicator 3.3.2.8 - 0 if packet is complete, nonzero specifies which error happened
        int m_completeMapaSdu; // used as packet quality indicator 3.3.2.8 - 0 if sdu is complete, nonzero specifies which error happened
        int m_rxcount;

        // to actually interface with the outside world
        void (*m_deliverFn)( unsigned char *data, int datalen, int type );
        void putDeliverFn( void (*thefn)(unsigned char *, int, int) ) { m_deliverFn = thefn; }

        ////////////////////////////// 
        // error reporting stats    //
        ////////////////////////////// 
        bool m_frameCountError; // a frame count error happened  (only way to know an octet stream data loss may have occurred)
        ////////////////////////////// 
        // error reporting stats    //
        ////////////////////////////// 
        int m_PktErrRxNewPacketWithNonEmptyAssemblyBuf; // received new packet START with incomplete OLD packet in rx assembly buffer
        int m_PktErrRxdContinuationWithNoBeginSegment; // received CONTINUATION packet with NOTHING in the rx assembly buffer (no beginning to tack this onto the end of)
        int m_MapaErrRxdStartingMapaWithNonEmptyAssemblyBuf; // received starting mapa with incomplete old MAPA in rx assembly buffer
        int m_MapaErrRxdContinuingMapaWithEmptyAssemblyBuf; // received continuing packet with NOTHING in the rx assembly buffer (no beginning to tack this onto the end of)
        int m_MapaErrRxdVarStartingMapaWithNonEmptyAssemblyBuf; // received starting mapa with Nonempty assembly buf IN VARIABLE FRAME
        int m_PktErrRxdVarStartingPacketWithNonEmptyAssemblyBuf; // received starting packet with NONempty assembly buf IN VARIABLE FRAME
        int m_PktErrRxdVarContinuingPacketWithEmptyAssemblyBuf; // received continuing packet with empty assembly buf IN VARIABLE FRAME
        int m_MapaErrRxdVarContinuingMapaWithEmptyAssemblyBuf;
        int m_PktErrRxdVarEndingSegPacketWithEmptyAssemblyBuf;
        int m_MapaErrRxdVarEndingSegMapaWithEmptyAssemblyBuf;
        int m_PktErrRxdPktEndspanWithTooShortRxAssemblyBuf;
        int m_MapaErrRxdVarConstRule111WithNonEmptyAssemblyBuf;
        int m_SdlsErrRxdWithNonEmptyAssemblyBuf;
        ////////////////////////////// 
        // local this-frame-ocf     //
        //////////////////////////////
        unsigned char m_mapid_ocfData[MAX_OCF_LENGTH];
        int m_mapid_ocfLength;
        int m_mapid_frameCounterOctets; // the number of frame counter octets after each addNewKlmPacket/SDU or octet stream
        ////////////////////////////////// 
        // new add packet variables     //
        //////////////////////////////////
        int m_copyToOutputIndex; // index into m_TxAssemblyBuf
        bool m_ccsdsPacket; // true if packet, false if MAPA (since the newKlmAddPacketSduTo_FIFO_Tx will only be called for packets and mapa )
        int m_constRules; // construction rules
        bool m_fixedlen; // true if this map is fixed lenght, false if variable
        bool m_completeInbuf; // copied entire inputBuf (packet or mapa) into the tx assembly buf
        bool m_beginSpan;	// only copied a begin span
        bool m_middleSpan; // only copied a middle span
        bool m_endSpan; // only copied an end span
        ////////////////////////////////// 
        // end new add packet variables //
        //////////////////////////////////
        // bool getPacketToTx (unsigned char *retrieveData, int *retrieveDataLen, bool *whatIGotWasQueueData);
        void constructPerMapHeader ( bool startsWithContinuation, bool continuesToNextFrame, bool isVariableLenFrame, int preFhpHdrLen, int fhplvo );
        kphysicalChannel* m_map_PHYSCHANptr;
        int m_map_MASTER_CHANNEL_ID;
        int m_map_MAPID;
        int m_map_VCID;
        int m_map_Spacecraft_ID ;
        int m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR; // total tfdf max length for a mapid. FRAME COUNTER OCTETS based on QoS must be subtracted from this. does handle required-or-possible ocf len (4) or always-absent-ocf-len (0)
        int m_map_ServiceDataUnitType; // packet/map_sdu/octet_stream
        int m_map_UslpProtocolIdSupported;
        int m_map_maxMsDelayToReleaseTfdfOnceStarted_fromvc; // as of oct 2016 new parameter (PROPAGATED FROM VCID for easy processing)
        bool m_txBufStartsWithContinuation; // flag to say tx assembly buf currently contains an end span (for tx-me-next consecutivity)
        int m_txBypassFlag; // bypass flag during tx
        int m_txThisPvnNext;
        int m_SduId;
        int m_map_octetStreamDeliverLength; // the length of accumulated octet stream to DELIVER
        int m_map_octetStreamRequestLength; // the length of accumulated octet stream expected when an octet REQUEST is performed
        bool m_octetStreamLossFlag;  // flag to say you've lost a frame.
        bool m_mapaSduFrameCountLossFlag;  // flag to say you've lost a frame DUE TO FRAME COUNT ONLY (other detections ignored so far, due to email by ed greenberg 2/6/2018 10:23)
        gmapid m_GMAPID; // version of MY gmapid

        //
        // "sap" stuff
        //
        struct m_outqEntry
        {
            int constrRules; // this can change every frame
            int fhplvo; // this can change every frame
            unsigned char packetdata[MAX_FRAME_SIZE];
        };
        union moqecharu
        {
            struct m_outqEntry mqe;
            unsigned char buf[sizeof(struct m_outqEntry)];
        } moquecharu;

        CircularPacketQueue * m_qSeqCtrlTfdfs; // separate queues for seqCtrl and Expedited
        CircularPacketQueue * m_qExpeditedTfdfs;
        PMutex m_qSeqCtrlTfdfs_mutex;
        PMutex m_qExpeditedTfdfs_mutex;
        // rx vars that are split into 2 based on QoS where sequenceControl0expedited1 is the index
        unsigned char *m_RxAssemblyBuf[2]; // for assembly of incoming parital packets rxd, separated by QoS, 0=sequenceCountrolled 1=expedited
        int m_RxAssemblyIndex[2]; // assembly index per pvn (where to add the next octets)
        int m_spanningPvn[2]; // if a packet spans you hafta add the end span to the correct pvn's rx-assembly-buffer (separated by QoS , 0=sequenceCountrolled 1=expedited)
        unsigned char m_TxAssemblyBuf[2*MAX_FRAME_SIZE]; // for adding idle packets to outgoing (txd) frames
        // klm407 int m_offsetToStartWritingToTxBuf; duplicate value to m_copyToOutputIndex // OFFSET to first empty byte in txassemblybuf. start adding at THIS offset
        int m_mapfhplvo; // per map, not per pvn
        long long m_usTimeToTransmitStartedTfdf; // time to empty the tfdf if started (affected by m_map_maxMsDelayToReleaseTfdfOnceStarted_fromvc)
        unsigned char m_permapheader[MAX_TFDF_HEADER_SIZE]; // one header for all pvns since it's all the same map - and now the size is 3 because they removed the extended protocol byte
        int m_permapheaderLen; // total header len (known after you get protocol id from MAP config and frame type (fixed/var) from VCID config
        int m_fhplvoOffset; // since ONE map has ONE protocol id, there will be ONE offset for all pvns in header to fhp/lvo (depends on whether extended protocol id octet is used) - as of oct 2016, NO extendedProtocol ID will exist

        // this below variable is MAP_CHANNEL_Maximum_TFDF_Length - tfdf Header size
        int m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets;  // avialable octets NOT COUNTING frame counter octets
        int m_protocolCommandControlFlag; // described in 4.1.2.8.2
        kvcid *m_myVcidParent;

        kmapid ( kphysicalChannel *physchan, int masterchannelid, int vcid, int mapid, kvcid *ptrToVcidParent ); // default constructor
        // bool newKlmAddOctetStreamToFifo( unsigned char *inputPacket, int inputLen, int sequenceControl0expedited1);
        bool newKlmAddOctetStreamTo_QUEUE_Tx( unsigned char *inputPacket, int inputLen/*2/21/2018 4:25pm greg kazz email removes this , int sequenceControl0expedited1*/);
        bool newKlmAddPacketSduTo_FIFO_Tx ( unsigned char *inputPacket, int totalInputBytes, int pvn, int sequenceControl0expedited1, bool realtime);
        bool newKlmAddPacketSduTo_QUEUE_Tx ( unsigned char *inputPacket, int totalInputBytes, int pvn, int sequenceControl0expedited1, bool realtime);
        bool mapBuildAndTxTruncatedFrame( unsigned char *data, int lagmcid, int lvcid, int lmapid); // below kvcid because it uses my_parentVcid
        bool TXtoQueue( int txBypassFlag, const char *status ); // queue implementation
        //NOTE THAT for TXFromQueue headerAndData INCLUDES TX BYPASS FLAG in position [0]
        //NOTE THAT for TXFromQueue headerAndData INCLUDES TX BYPASS FLAG in position [0]
        //NOTE THAT for TXFromQueue headerAndData INCLUDES TX BYPASS FLAG in position [0]
        // replacing with two-queue solution bool TXfromQueue( unsigned char *headerAndData, int headerAndDataLen, const char *status ); // TODO eliminate status
        bool TXfromQueue( int sequencecontrol0expedited1, unsigned char *headerAndData, int headerAndDataLen, const char *status ); // TODO eliminate status
        //bool TX( const char *status );
        bool klmcheckForMapData( void ) // this FORCES a partial frame to be transmitted if it's steenkin TIME to transmit
        {
            //
            //
            // rewrite this to check BOTH queues if this is ever uncommented
            //
            //
            klmprintf("IN checkForMap %d/%d @ %lld gtpktcnt %ld moff %d gtn %lld ttetdf %lld\n",m_map_VCID, m_map_MAPID,globalUsTimeNow,m_qSeqCtrlTfdfs->get_packet_count(),m_copyToOutputIndex,globalUsTimeNow,m_usTimeToTransmitStartedTfdf );fflush(stdout); // TODO handle error
            bool retval = false;
            m_qSeqCtrlTfdfs_mutex.lock();
            // check output Queue first
            if ( m_qSeqCtrlTfdfs->get_packet_count() > 0 )
            {
                klmprintf("checkForMap 2 %d/%d Data at %lld: pktcnt > 0\n",m_map_VCID, m_map_MAPID,globalUsTimeNow);fflush(stdout); // TODO handle error
                retval = true;
            }
            else if ( m_copyToOutputIndex > 0 && globalUsTimeNow >= m_usTimeToTransmitStartedTfdf) // if there's leftover data in the txassemblyBuf AND it's time to tx
            {
                klmprintf("checkForMap 3 %d/%d Data: moffset %d > 0 - %d \n",m_map_VCID, m_map_MAPID, m_copyToOutputIndex, m_copyToOutputIndex);fflush(stdout); // TODO handle error
                retval = true;
            }
            else 
            { 
                klmprintf("checkForMap 4 %d/%d was neither true?\n",m_map_VCID, m_map_MAPID);fflush(stdout); // TODO handle error 
            } 
            // klmprintf("check4map %d data offset %d, ttetfdf %d glonow %d\n",m_map_MAPID, m_copyToOutputIndex, m_usTimeToTransmitStartedTfdf, globalUsTimeNow); fflush(stdout);
            m_qSeqCtrlTfdfs_mutex.unlock();
            return retval;
        }
        int getPvn (unsigned char firstOctet) 
        {
            return (firstOctet & 0xff) >> 5;
        }
        void errstats(void)
        {
            klmprintf("                                    m_PktErrRxNewPacketWithNonEmptyAssemblyBuf         = %d\n", m_PktErrRxNewPacketWithNonEmptyAssemblyBuf); 
            klmprintf("                                    m_PktErrRxdContinuationWithNoBeginSegment          = %d\n", m_PktErrRxdContinuationWithNoBeginSegment); 
            klmprintf("                                    m_PktErrRxdPktEndspanWithTooShortRxAssemblyBuf     = %d\n", m_PktErrRxdPktEndspanWithTooShortRxAssemblyBuf);
            klmprintf("                                    m_MapaErrRxdStartingMapaWithNonEmptyAssemblyBuf    = %d\n", m_MapaErrRxdStartingMapaWithNonEmptyAssemblyBuf); 
            klmprintf("                                    m_MapaErrRxdContinuingMapaWithEmptyAssemblyBuf     = %d\n", m_MapaErrRxdContinuingMapaWithEmptyAssemblyBuf); 
            klmprintf("                                    m_PktErrRxdVarStartingPacketWithNonEmptyAssemblyBuf= %d\n", m_PktErrRxdVarStartingPacketWithNonEmptyAssemblyBuf); 
            klmprintf("                                    m_PktErrRxdVarContinuingPacketWithEmptyAssemblyBuf = %d\n", m_PktErrRxdVarContinuingPacketWithEmptyAssemblyBuf); 
            klmprintf("                                    m_PktErrRxdVarEndingSegPacketWithEmptyAssemblyBuf  = %d\n", m_PktErrRxdVarEndingSegPacketWithEmptyAssemblyBuf);
            klmprintf("                                    m_MapaErrRxdVarStartingMapaWithNonEmptyAssemblyBuf = %d\n", m_MapaErrRxdVarStartingMapaWithNonEmptyAssemblyBuf); 
            klmprintf("                                    m_MapaErrRxdVarContinuingMapaWithEmptyAssemblyBuf  = %d\n", m_MapaErrRxdVarContinuingMapaWithEmptyAssemblyBuf);
            klmprintf("                                    m_MapaErrRxdVarEndingSegMapaWithEmptyAssemblyBuf   = %d\n", m_MapaErrRxdVarEndingSegMapaWithEmptyAssemblyBuf);
            klmprintf("                                    m_MapaErrRxdVarConstRule111WithNonEmptyAssemblyBuf = %d\n", m_MapaErrRxdVarConstRule111WithNonEmptyAssemblyBuf);
            fflush(stdout);
        }
        //
        // rx one whole packet, deliver to user
        //
        void deliverToUser ( unsigned char * dataToUser, int dataLen, int pvn , int type); // deliver one unit of data to user
        //
        // parse packets starting at buf[0], leave excess in m_RxAssemblyBuf and leave m_RxAssemblyIndex[sqexp] pointing at first octet to write NEXT
        // affects ****m_spanningPvn***
        // returns false if not enough there to find packet length, OR if DID find packet length and it's not all there yet (an error situation if the last thing you put in was an end span)
        //
        bool parsePacketsFromBufLeaveExcessInRxAssemblyBuf ( unsigned char *buf, int bufLen , int sqc0exp1)
        {
            bool retval = true; // did complete on boundary
            int lbufIndex = 0; // packet needs to start at buf[0]
            int lpktlen;
            int lpvn;
            while ( (lbufIndex < bufLen) && ! isEncapsulatedIdlePacket ( buf, lbufIndex , (bufLen - lbufIndex)) )  // while not pointing at an idle fill (which indicates fill to the end of the tfdf and can be dropped)
            {
                lpktlen = getPacketLength(&buf[lbufIndex], bufLen - lbufIndex); // of the remaining bytes in this buf chunk
                lpvn = getPvn(buf[lbufIndex]); // get pvn from first octet
                klmprintf("***** index %d lpktlen %d buflen %d pvn %d \n",lbufIndex, lpktlen, bufLen, lpvn);fflush(stdout);
                if ( (lpktlen >= 0) && (lbufIndex + lpktlen ) <= bufLen ) // entire packet is in this buf
                {
                    kprMutex.lock();printf("***** complete pkt len %d ",lpktlen);seedata(&buf[lbufIndex],lpktlen);printf("\n");fflush(stdout);kprMutex.unlock();
                    deliverToUser( &buf[lbufIndex], lpktlen, lpvn, eMAP_PACKET);
                    // 
                    // adding mapp_notify_indication and mapp_indication for compliance matrix
                    // 
                    add_packet_indications(&buf[lbufIndex], m_GMAPID, m_txBypassFlag, m_SduId, 0,false/*ok*/,SDLSverificationStatusCodeGetter()); // notification type = 0 = nothing wrong , bool packetQualityIndicatorError = 0; verificationStatusCode )
                    // 
                    // [ ] verified?
                    // 
                    lbufIndex += lpktlen;
                    if ( lbufIndex == bufLen ) // if you just delivered a packet that exactly filled the assembly buffer with nothing left over
                    {
                        m_RxAssemblyIndex[sqc0exp1] = 0; // if it filled it exactly, nothing to copy, just reset assembly index
                    }
                }
                else // packet does not end in this tfdf or not enough octets to GET packet length - 
                {
                    int lendingOctets = bufLen - lbufIndex; // how may octets are left in the frame
                    // use memmove because may be copying from the end of m_RxAssemblyBuf to beginning of m_RxAssemblyBuf
                    memmove( m_RxAssemblyBuf[sqc0exp1], &buf[lbufIndex], lendingOctets ); // copy remainder of buf to rx assembly buffer
                    m_spanningPvn[sqc0exp1] = lpvn; // expect next buf field to be for this pvn
                    m_RxAssemblyIndex[sqc0exp1] = lendingOctets;
                    kprMutex.lock();printf("***** spanning pkt len %d at %d ",lendingOctets,lbufIndex);seedata(&buf[lbufIndex],lendingOctets);printf("\n");fflush(stdout);kprMutex.unlock();
                    lbufIndex += lendingOctets;
                    retval = false; // THIS IS USED in constr rule 000 if endspan addition is still too short for inherent length - means you missed the continuation segment. deliver concatenated packet and mark it as errored
                }
            }	
            return retval; // return false if left the first of a spanning packet in m_rxAssemblyBuf[lpvn]
        }
        // 
        // received a frame with a KNOWN starting position of 0 while there's an unfinished packet in m_RxAssemblyBuf. deliver to user ONLY if MP says to.
        // 
        void deliverPartialSDU ( unsigned char *buf, int buflen, int pkterr, int sqc0exp1 ); // deliver one unit of data to user
        //
        //
        //
        //
        //
        // this routine receives a single frame's TFDF, parses/concatenates any packets and delivers individual packets to user
        //
        //
        //
        //
        //
        void deliverDataField ( int constrRules,int protocolId, int fhplvo, unsigned char * data, int dataLen , int protocolCommandControlFlag , int sequenceControl0expedited1); // permapid has INHERENT m_frameCounter access
        void deliverRawDataFromTruncatedFrame(String &physchan, int mcid, unsigned char *truncatedRawData );
        //
        // these can't be written here because they need kvcid info
        // void mKLMQapTxStartedTfdfTimerExpired(kphysicalChannel *kpcptr,kmasterChannel *kMCptr, kvcid *kvcptr, kmapid *kmapidptr );
        void mapTxStartedTfdfTimerExpired(void); // signature for when you already know the map_id and have used it to access the right function
        void mapp_notify_indication(gmapid GMAPID, int pvn, int sduid, int qos, int notificationType)
        {
            //
            // TODO need a map between errors i find and SPEC errors
            //  ePktErrRxdContinuationWithNoBeginSegment = 
            //
            klmprintf("mni klmq GMAPID %s-%6d-%1d-%1d-%1d Qos %d sduid %d notificationType %s\n",
                    GMAPID.PHYSCHAN.c_str(),  // physchan
                    ((GMAPID.TFVN * 65536) + GMAPID.SCID),  // mcid
                    GMAPID.VCID, // vcid
                    GMAPID.MAPID, // mapid
                    pvn, // pvn (in first octet)
                    qos, // quality of service
                    sduid, // sdu id
                    notificationString[notificationType]);fflush(stdout);
            m_SduId++; // gets bumped every notify indication
        }
        void mapp_indication(unsigned char *packet, gmapid GMAPID, int packetVersionNumber, int QoS, bool packetQualityIndicatorError = false, int verificationStatusCode = 0);
        //
        // calculates pvn from first octet of *packet and calls notify_indication and indication to comply with uslp spec
        //
        void add_packet_indications(unsigned char *packet, gmapid GMAPID, int qos, int sduid, int notificationType, bool packetQualityIndicatorError = false, int verificationStatusCode = 0)
        {
            int lpvn = 0;
            if ( notificationType != 0 )  // only get pvn on good packets
            {
                lpvn = getPvn (*packet);
            }
            // nope - this doesn't go here. mapp_notify_indication(GMAPID, lpvn, sduid, qos, notificationType);
            mapp_indication(packet, GMAPID, lpvn, qos, packetQualityIndicatorError/*true if error*/, verificationStatusCode);
        }
        //
        // MAPA_SDU
        //
        void mapasdu_notify_indication(gmapid GMAPID, int sduid, int qos, int notificationType)
        {
            //
            // TODO need a map between errors i find and SPEC errors
            //  ePktErrRxdContinuationWithNoBeginSegment = 
            //
            klmprintf("mapasdu_notify_indication GMAPID %s-%6d-%1d-%1d Qos %d sduid %d notificationType %s\n",
                    GMAPID.PHYSCHAN.c_str(),  // physchan
                    ((GMAPID.TFVN * 65536) + GMAPID.SCID),  // mcid
                    GMAPID.VCID, // vcid
                    GMAPID.MAPID, // mapid
                    qos, // quality of service
                    sduid, // sdu id
                    notificationString[notificationType]);fflush(stdout);
            m_SduId++; // gets bumped every notify indication
        }
        void mapasdu_indication(unsigned char *mapaSdu, gmapid GMAPID, int qos = 0, bool mapaSduLossFlag = false, int verificationStatusCode = 0);
        //
        // send out the mapasdu_notify_indication and mapasdu_indications
        //
        int SDLSverificationStatusCodeGetter(void)
        {
            static int code =0;
            int retval = code++;
            if ( code >= TOTAL_VERIFICATION_STATUS_CODES )
            {
                code = 0;
            }
            return retval;
        }
        void add_mapasdu_indications(unsigned char *mapaSdu, gmapid GMAPID, int qos, int sduid, int notificationType, bool mapaSduRxError = false, int verificationStatusCode = 0)
        {
            //
            // NOTE: mapaSduRxError ignored. RxError detects things like consecutive starting span with no continuing/ending span. 
            // NOTE: 3.4.2.6.3 says (and ed greenberg confirms in 2/6/2018 10:23 email) that a mapasdu loss flag is ONLY to be true if FRAME COUNT ANOMALY and then only if this mapid is only mapid on vcid
            //       the value that contains that fact is m_mapaSduFrameCountLossFlag
            //
            // nope - this doesn't go here mapasdu_notify_indication(GMAPID, sduid, qos, notificationType);
            //
            // pass m_mapaSduFrameCountLossFlag onto indication (ONLY indicate loss if frame count anomaly AND THEN ONLY if this mapid is the only one on the vcid
            //
            mapasdu_indication(mapaSdu, GMAPID, qos, m_mapaSduFrameCountLossFlag, verificationStatusCode); // mapa frame loss can be from outof sequence error or partial delivery
        }
        //
        // send out the octetStream_indications (there's no notify AND indication, it's jsut a request 3.5.3.2.2 and indication 3.5.3.3.1)
        //
        void map_octetStream_indication(unsigned char *octetStreamData, gmapid GMAPID, /*qos removed 2/21/2018 4:25 greg kazz email int qos = 0,*/ bool octetStreamLossFlag = false, int verificationStatusCode = 0);
};
class kvcid
{
    public:
        int killthisDummyVcRxFrameCounter;
        int killthisDropNframes; // drop this many every killthisDropEveryNframes frames
        int killthisDropEveryNframes;
        bool killthisDroppingFrames;
        void killthisVcFrameDropper(int dropN, int dropEveryN )
        {
            killthisDropNframes = dropN;
            killthisDropEveryNframes = dropEveryN;
        }
        char m_parentstr[100];
        unsigned char *m_vcid_pcOidData; // propagate PC oid info

        // ocf buffer
        // klm918 moved to mcid unsigned char m_vcid_ocfBuf[MAX_OCF_LENGTH];
        // klm918 moved to mcid int m_vcid_ocfLen; // local copy of ocf length (length of zero says there's no ocf)
        // klm918 moved to mcid PMutex m_ocfbuf_mutex;

        kphysicalChannel* m_myPHYSCHAN; 
        kmasterChannel *m_myMCID; 

        bool (*m_farmfn)(int sequencecount);
        void putFarmFn( bool (*thefn)(int) ) { m_farmfn = thefn; }
        kvcid ( kphysicalChannel *lmyphyschanptr, kmasterChannel *lmymasterchannelid, int lvcid );
        long long m_vcidUsTimeToTxMinTimeBetweenVcidFrames; // the time IN MICROSECONDS to tx an OID frame complying with 4.1.4.1.6 (this timer is bumped by the maxMsBetweenreleases... timer every vc tx) 
        int m_source0Destination1; // if this bit is 1 then the spacecraft ID in the mcid is the DESTINATION spacecraft id. if 0 it's the source. if parent mcid's spacecraft id isn't MY_SPACECRAFT_ID this will be set to 'destination'
        int m_VCID;
        int m_vcid_Transfer_Frame_Type;
        int m_vcid_Maximum_Transfer_Frame_Length;
        int m_vcid_VCID; 
        int m_vcSeqCtrlCountOctets; // how many octets for this vcid (0-7)
        int m_vcExpIntCountOctets; // how many octets for this vcid (0-7)
        int m_COP_in_Effect;
        int m_CLCW_Version_Number;
        String m_CLCW_Reporting_Rate;
        bool m_vc_MAP_IDs[MAX_MAP_IDS];
        int m_vc_MAP_Multiplexing_Scheme;
        int m_truncatedFrameTotalLength; // TODO nobody uses this yet
        int m_allowVariableFrameInclusionOfOcf;
        int m_vcRequireFixedFrameInclusionOfOcf;
        int m_Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_service_data_on_the_Sequence_Controlled_Service; // limited by physchan value
        int m_RepetitionsValueUNLIMITEDbyPhyschanValue; // for expedited frames only // NOT limited by physchan value
        int m_Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_COP_control_commands; // limited by physchan value
        int m_Maximum_delay_in_milliseconds_between_releases_of_frames_of_the_same_VC; // different than the 'once started' - this is "when there's NOTHING, tx an idle frame"
        bool m_timedVcidReleasesFlag; // flag to say there are NO timed releases (or that there are - true = are)
        int m_vc_maxMsDelayToReleaseTfdfOnceStarted; // here in mibconfig but value propagated down to map
        int m_lastFrameReleaseTime; // time of last tx on this vcid
        int m_vc_include_OCF; // quickie flag to say if we deliver/expect OCF (calculated from m_vcid_Transfer_Frame_Type and m_allowVariableFrameInclusionOfOcf/m_vcRequireFixedFrameInclusionOfOcf by readMibConfig for speedy real-time processing)
        PMutex m_txMeNext_mutex;

        bool m_VcidFrameService; // this is a vcid-frame-service vcid
        bool m_vcidFrameServiceFrameLoss; // loss detected by frame count error 
        gvcid m_GVCID; // my GVCID to pass to everybody (so far only vc frame service needs this)
        bool m_oneMapidOnThisVcid; // mapa sdu frame loss flag only true if it's the only mapid on this vcid (uslp redbook 3.4.2.6.2)



        std::map <int,kmapid *> m_mapmap;
        std::map <int,kmapid *>::iterator m_mapidit; // only used in getSoonestTimeExpiration()

        // vc frame service queue
        CircularPacketQueue * m_qVcFrameService;
        PMutex m_qVcFrameService_mutex;

        long long m_vcmaxval[8]; // max value for vc counter of specified number of octets
        // other stats
        long long m_vcSeqCtrlCountMax;      // the rollover
        long long m_vcSeqCtrlCounter;     // the current frame count

        long long m_vcExpIntCountMax;     // the rollover
        long long m_vcExpIntCounter;      // the current frame count
        PMutex tx_mutex;


        // per-vcid security header string

        int m_PresenceOfSpaceDataLinkSecurityHeader;
        int m_LengthOfSpaceDataLinkSecurityHeader;
        unsigned char m_spaceDataLinkSecurityHeader[MAX_FRAME_SIZE]; // this is per-vcid now
        int m_PresenceOfSpaceDataLinkSecurityTrailer;
        int m_LengthOfSpaceDataLinkSecurityTrailer;
        unsigned char m_spaceDataLinkSecurityTrailer[MAX_FRAME_SIZE];

        void resetVcidOidTimer(void);
        char *vcktree(void);
        void putVcidSecurityHeader ( unsigned char * secHdrStr )
        {
            memcpy ( m_spaceDataLinkSecurityHeader, secHdrStr, m_LengthOfSpaceDataLinkSecurityHeader );
        }
        void putVcidSecurityTrailer ( unsigned char * secTrlrStr )
        {
            memcpy ( m_spaceDataLinkSecurityTrailer, secTrlrStr, m_LengthOfSpaceDataLinkSecurityTrailer );
        }
        int getVcFrameQueueSize ( void )
        {
            return m_qVcFrameService->get_packet_count();
        }
        /*
           bool putqVcFrameService ( unsigned char * vcFrameServiceData, int nbytes )
           {
           m_qVcFrameService_mutex.lock();
           bool goodappend = m_qVcFrameService->append ( vcFrameServiceData,nbytes ) ;
           m_qVcFrameService_mutex.unlock();
           if ( ! goodappend )
           {
           klmprintf ( "VcFrame NOT appended - still %d VcFrameServices in queue\n",getVcFrameQueueSize() );
           fflush ( stdout );
           }
           else
           {
           klmprintf ( "%d VcFrame Services in queue\n",getVcFrameQueueSize() );
           fflush ( stdout );
           }
           return goodappend;
           }
           bool getqVcFrameService ( unsigned char * ptrToVcFrameService, int * ptrToLength )
           {
           bool goodretrieve = true;
           if ( getVcFrameQueueSize() == 0 )
           {
        // klmprintf ( "empty vc frame service queue\n" ); fflush ( stdout );
        goodretrieve = false;
        }
        else
        {
        m_qVcFrameService_mutex.lock();
        int qVcFrameServiceSize = m_qVcFrameService->retrieve ( ptrToVcFrameService,*ptrToLength ); // give it a length you want
        m_qVcFrameService_mutex.unlock();
        if ( qVcFrameServiceSize == 0 )
        {
        // klmprintf ( "retrieved zero len VcFrameService\n" ); fflush ( stdout );
        goodretrieve = false;
        }
        else
        {
        goodretrieve = true;
         *ptrToLength = qVcFrameServiceSize; // return how many bytes you DID get in ptrToLength
         kprMutex.lock();printf ( "got VcFrameService: " ); seedata ( ptrToVcFrameService,*ptrToLength ); printf ( "\n" ); fflush ( stdout );kprMutex.unlock();
         }
         }
         return goodretrieve;
         }
         */
        void setVcSeqCtrlOctets ( int octets )
        {
            if ( octets >= 0 && octets <= 7 )
            {
                m_vcSeqCtrlCountOctets = octets;
                m_vcSeqCtrlCountMax = m_vcmaxval[octets];
            }
            else
            {
                kerror ( "bad vc octets value %d\n",octets );
            }
        }
        void setVcExpIntOctets ( int octets )
        {
            if ( octets >= 0 && octets <= 7 )
            {
                m_vcExpIntCountOctets = octets;
                m_vcExpIntCountMax = m_vcmaxval[octets];
            }
            else
            {
                kerror ( "bad vc octets value %d\n",octets );
            }
        }
        int getVcFrameCounterOctets ( int sequenceControl0expedited1 ) 
        {
            int retval;
            if ( sequenceControl0expedited1 == 0 )
            {
                retval = m_vcSeqCtrlCountOctets; // this many octets
            }
            else // expedited counter
            {
                retval = m_vcExpIntCountOctets; // this many octets
            }
            return retval;
        }
        long long getVcFrameCounterAndInc ( int sequenceControl0expedited1 ) 
        {
            long long retval;
            if ( sequenceControl0expedited1 == 0 )
            {
                retval = m_vcSeqCtrlCounter++; // get counter and inc
                // check for wrap
                if ( m_vcSeqCtrlCounter >= m_vcSeqCtrlCountMax )  // max is one more than legal value, like MAX_SOMETHING_IDS
                {
                    m_vcSeqCtrlCounter = 0;
                }
            }
            else // false - expedited counter used
            {
                retval = m_vcExpIntCounter++; // get counter and inc
                // check for wrap
                if ( m_vcExpIntCounter >= m_vcExpIntCountMax )  // max is one more than legal value, like MAX_SOMETHING_IDS
                {
                    m_vcExpIntCounter = 0;
                }
            }
            return retval;
        }
        void copDirectiveRequestReceivedByReceiver(unsigned char *frame, gvcid GVCID, int lframelen, int whichcop ) 
        {
            charint lca;
            //
            // GVCID has already been verified.
            //
            // start of frame depends on vc counter len.
            lca.i = 0;
            lca.c[0] = frame[6] & 0x07;
            int lframeIndex = FRAME_HEADER_LENGTH + lca.i + 1; // cop must be in expedited frame plus one to skip over tfdf header (constr rule 111 and upid 1 or 2)
            //
            lca.i = 0;
            lca.c[0] = frame[lframeIndex++];
            int dirid = lca.i;
            lca.i = 0;
            lca.c[0] = frame[lframeIndex++];
            int nottype = lca.i;
            lca.i = 0;
            lca.c[0] = frame[lframeIndex++];
            int notqualifier = lca.i;
            int lportId = 9; // illegal value for cop-P, but get the 4th octet anyway to move pointer to CRC
            lca.i = 0;
            lca.c[0] = frame[lframeIndex++];
            lportId = lca.i; // get the 4th octet port id
            if ( memcmp((void *)&frame[lframeIndex],(void *)COP_DUMMY_CRC,4) != 0 )
            {
                kprMutex.lock();printf( "dTu Cop CRC mismatch - expecting %s got '",COP_DUMMY_CRC);seedata(&frame[lframeIndex],4);printf("'\n");fflush(stdout);kprMutex.unlock();
            }
            lframeIndex += 4; // include CRC in total frame len.
            if ( whichcop == CopPInEffect ) // 
            {
                klmprintf ( "dTu cop-P DirectiveRequestReceivedByReceiver %s-%d-%d portId %d<",GVCID.PHYSCHAN.c_str(), (GVCID.TFVN * 65536) + GVCID.SCID, GVCID.VCID, lportId);   // fall through to switch() klmprintfs/fflush
            }
            else // cop-1 (vcid)
            {
                klmprintf ( "dTu cop-1 DirectiveRequestReceivedByReceiver %s-%d-%d <",GVCID.PHYSCHAN.c_str(), (GVCID.TFVN * 65536) + GVCID.SCID, GVCID.VCID);   // fall through to switch() klmprintfs/fflush
            }
            switch ( nottype )
            {
                case cdt_initiateAdServiceWithoutClcwCheck:
                    klmprintf("> dirid %3d dirtype cdt_initiateAdServiceWithoutClcwCheck, dirqual %d ",dirid,notqualifier);fflush(stdout);
                    break;
                case cdt_initiateAdServiceWithClcwCheck: 
                    klmprintf("> dirid %3d dirtype cdt_initiateAdServiceWithClcwCheck , dirqual %d ",dirid,notqualifier);fflush(stdout);
                    break;
                case cdt_initiateAdServiceWithUnlock: 
                    klmprintf("> dirid %3d dirtype cdt_initiateAdServiceWithUnlock , dirqual %d ",dirid,notqualifier);fflush(stdout);
                    break;
                case cdt_initiateAdServiceSetVr: 
                    klmprintf("> dirid %3d dirtype cdt_initiateAdServiceSetVr , dirqual %d ",dirid,notqualifier);fflush(stdout);
                    break;
                case cdt_terminateAdService: 
                    klmprintf("> dirid %3d dirtype cdt_terminateAdService , dirqual %d ",dirid,notqualifier);fflush(stdout);
                    break;
                case cdt_resumeAdService: 
                    klmprintf("> dirid %3d dirtype cdt_resumeAdService , dirqual %d ",dirid,notqualifier);fflush(stdout);
                    break;
                case cdt_setVsToVs: 
                    klmprintf("> dirid %3d dirtype cdt_setVsToVs , dirqual %d ",dirid,notqualifier);fflush(stdout);
                    break;
                case cdt_setFopSlidingWindowWidth: 
                    klmprintf("> dirid %3d dirtype cdt_setFopSlidingWindowWidth , dirqual %d ",dirid,notqualifier);fflush(stdout);
                    break;
                case cdt_setT1initial: 
                    klmprintf("> dirid %3d dirtype cdt_setT1initial , dirqual %d ",dirid,notqualifier);fflush(stdout);
                    break;
                case cdt_setTransmissionLimit: 
                    klmprintf("> dirid %3d dirtype cdt_setTransmissionLimit , dirqual %d ",dirid,notqualifier);fflush(stdout);
                    break;
                case cdt_setTimeoutType: 
                    klmprintf("> dirid %3d dirtype cdt_setTimeoutType , dirqual %d ",dirid,notqualifier);fflush(stdout);
                    break;
                default:
                    klmprintf("> dirid %3d dirtype indeterminate , dirqual %d ",dirid,notqualifier);fflush(stdout);
                    break;
            }
            kprMutex.lock();printf("frame: ");seedata ( frame, lframeIndex ); printf("\n");fflush(stdout);kprMutex.unlock();
        }
        void vc_frame_service_indication(unsigned char *frame, gvcid GVCID, bool vcFrameServiceFrameLossFlag=false ) // frame loss flag
        {
            charint lkci;
            lkci.i = 0;
            lkci.c[0] = frame[5]; // lsb
            lkci.c[1] = frame[4]; // msb
            int lframelen = lkci.i + 1; // since frame length in the frame is minus-1
            kprMutex.lock();printf ( "vc_frame_service_indication %s-%d-%d lossFlg=%s <",GVCID.PHYSCHAN.c_str(), (GVCID.TFVN * 65536) + GVCID.SCID, GVCID.VCID, vcFrameServiceFrameLossFlag?"true":"false"); seedata ( frame, lframelen ); printf ( ">\n" ); fflush ( stdout );kprMutex.unlock();
            m_vcidFrameServiceFrameLoss = false; // reset vcFrameServiceFrameLossFlag on delivery
        }
        void deliverVcidFrameServiceFrame ( String & physchan, int mcid, unsigned char * frame,int framelen )
        {
            // just the data
            kprMutex.lock();printf ( "dTu VCid Frame Service frame to %s mcid %d vcid %02d: ",physchan.c_str(), mcid, m_VCID ); seedata ( frame, framelen ); printf ( "\n" ); kprMutex.unlock();
            fflush ( stdout );
            vc_frame_service_indication(frame,m_GVCID,m_vcidFrameServiceFrameLoss); 
        }
        void deliverCopServiceFrame ( String & physchan, int mcid, unsigned char * frame, int framelen, int copInEffect)
        {
            if ( copInEffect != noCopInEffect )
            {
                // just the data
                kprMutex.lock();printf ( "dTu sDu COP Service %d frame to %s mcid %d vcid %02d: ",copInEffect, physchan.c_str(), mcid, m_VCID ); seedata ( frame, framelen ); printf ( "\n" ); fflush ( stdout );kprMutex.unlock();

                copDirectiveRequestReceivedByReceiver(frame,m_GVCID,framelen,copInEffect); 
            }
        }
        // bool txQueuedTfdf(long long lusTimeNow); // will move vcid time-to-tx timer.
        long long getSoonestTimerExpiration(void) // find the soonest thing to do and return its time and mapid (mapid = -1 if the soonest thing to do is a time-between-vcid-frames thing instead of unfinishedTfdf)
        {
            long long lminTime = FOREVER_IN_THE_FUTURE;
            for ( m_mapidit = m_mapmap.begin(); m_mapidit != m_mapmap.end(); m_mapidit++ )
            {
                if ( m_mapidit->second->m_usTimeToTransmitStartedTfdf < lminTime ) // only mapids with something in their tfdf
                {
                    lminTime = m_mapidit->second->m_usTimeToTransmitStartedTfdf;
                }
            }
            // 
            // now check vcid's msBetweenVcidFrames timer
            // 
            if ( m_vcidUsTimeToTxMinTimeBetweenVcidFrames < lminTime )
            {
                lminTime = m_vcidUsTimeToTxMinTimeBetweenVcidFrames;
            } 
            return lminTime; // minimum time to wait until (the above timers will be either soon or FOREVER_IN_THE_FUTURE )
        }
        void minMsBetweenVcidFramesTimerExpired(void)
        {
            // if there's something in a tfdf somewhere i can transmit, transmit IT; otherwise, send an OID frame (regardless of generateOIDFrame spec on the physchan?)

        }
        bool getVcidOcfBuf ( unsigned char * ptrToOcf, int * ptrToLength );
        // klm918 decrementedUponGet() void decrementMCidOcfDeliveryCount ( void ); // decrement the number of times this ocf needs to be delivered
};
//
// only deal with "does this input require queueing-and-emptying of the TFDF"
//
bool kmapid::newKlmAddPacketSduTo_QUEUE_Tx ( unsigned char *inputPacket, int totalInputBytes, int pvn, int sequenceControl0expedited1, bool realtime)
{
    // m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR - m_mapid_frameCounterOctets - maximum tfdf length 
    //
    //  may hafta do some wierd stuff with stuff that's in there NOW before adding this, namely 
    //    tx2queue if new inputPacket won't fit (if varlen frame)
    // 	  tx2queue if new Qos var&fixed
    //

    bool goodappend = true; // good result if only add to buffer. only false if TXtoQueue returns false
    int lroomLeftInOutput; // running total of octets left in transmit assembly buffer
    if ( sequenceControl0expedited1 == eSequenceControlled )
    {
        m_qSeqCtrlTfdfs_mutex.lock();
    }
    else
    {
        m_qExpeditedTfdfs_mutex.lock();
    }
    // 
    // called by packet and MAPA_sdu
    // 
    if ( m_ccsdsPacket ) // only check pvns for packet
    {
        if ( packetInfoMib.m_Valid_Packet_Version_Numbers[pvn] == false)
        {
            if ( sequenceControl0expedited1 == eSequenceControlled )
            {
                m_qSeqCtrlTfdfs_mutex.unlock();
            }
            else
            {
                m_qExpeditedTfdfs_mutex.unlock();
            }
            return false;
        }
    }
    int lcopyFromInputIndex = 0; // where to start copying from

    ////////////////////////////////////////////////////////////////////////////////////
    // get local latest copy of ocf in case new one has arrived since last time through here OR current one has already been sent enough times (will return 0 length)
    ////////////////////////////////////////////////////////////////////////////////////

    //klm918 int locfLen;
    //klm918 unsigned char locfData[MAX_OCF_LENGTH]; 
    //klm918 m_myVcidParent->getVcidOcfBuf(locfData,&locfLen); // check to see if new OCF has arrived 
    m_mapid_frameCounterOctets = m_myVcidParent->getVcFrameCounterOctets(m_txBypassFlag);  // current frame count counter octets based on CURRENT bypass flag
    int lmaxTfdfLen = m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR - m_mapid_frameCounterOctets; // find real max len allowing for seq/exp fco

    ////////////////////////////////////////////////////////////////////////////////////
    //
    // handle "something already in the buffer" situation (either packet endspan (fixedlen) or complete packet (varlen) which can have another complete packet added to it)
    //
    // this may involve a different length of frame counter octets due to different bypass flag
    //
    ///////////////////////////////////////////////////////////////////////////////////

    if ( m_copyToOutputIndex > 0 ) // something already in buffer before addition
    {
        // two situations where you have a non-empty tx buffer that must be emptied upon receipt of this pkt/SDU:
        // 
        //  1) this recently-delivered packet won't fit (var pkt <CR_111_SEGMENT_STARTS_AND_ENDS>) (var mapaSdus that fit in one tfdf are tx2qd before leaving the NewKlmAddPacketSduTo_QUEUE_Tx() fn)
        //  OR
        //  2) you have a QoS (sequenceControl0expedited1) that's different than the current one (fixed or varlen, any <cr> )
        //
        if ( !m_fixedlen && m_map_ServiceDataUnitType == eMAP_PACKET ) // 1) will-this-new-packet-fit-in-var-tfdf-if-not-then-tx 
        {
            // how much room is left with these frame counter octets
            lroomLeftInOutput = lmaxTfdfLen - m_copyToOutputIndex; // use last datafieldOctets value before assigning new one
            if (lroomLeftInOutput < totalInputBytes ) // if new packet/sdu won't fit COMPLETELY in existing room, tx what's in there already
            {
                // tx2queue what's in there with current bypass flag and frame count octets
                goodappend = TXtoQueue(m_txBypassFlag, " <--- somethingInBufBeforeCopy, new pkt won't fit in varlen frame");  
                m_txBypassFlag = sequenceControl0expedited1;  // just emptied this frame, save bypass flag in member variable so next comparison won't retransmit an empty frame
            }
        }
        //
        // Second handle the situation where QoS (bypass flag) changes (so you use different frame counters and possibly different frame counter octets
        // may still be stuff in frame; if bypass flag is new, empty frame and start new frame with new SDU
        //
        if (m_txBypassFlag != sequenceControl0expedited1 )  // in either fixed or variable length frame, NEW QoS means new frame. if fixed len, idle fill, else tx as is
        {
            // tx what's in there now using existing construction rule, and existing frame counter octets
            if ( m_fixedlen ) // idle fill if fixedlen 
            {
                if ( m_ccsdsPacket && m_endSpan ) // 02062018 you're txing what's IN there already. it's either an END span or a complete packet. if it's an END span, the idle fill is the first good packet
                {
                    m_mapfhplvo = m_copyToOutputIndex; // first octet is FHP
                }
                lroomLeftInOutput = lmaxTfdfLen - m_copyToOutputIndex; // use last datafieldOctets value before assigning new one
                idleFillHere ( &m_TxAssemblyBuf[m_copyToOutputIndex], lroomLeftInOutput, m_map_pcOidData ); // ok to idle fill fixedlen - LVO says the end of SDU
                m_copyToOutputIndex += lroomLeftInOutput; // move index to reflect new data in tx asm buf
            }
            // else varlen - leave as is.
            goodappend = TXtoQueue(m_txBypassFlag, " <--- somethingInBufBeforeCopy, packet, NEW QoS ");   // tx with current bypass flag
        }
    }
    //
    // now done every exceptional thing, deal with NEW ocf, NEW bypass flag, and NEW packet/sdu
    //
    // new QoS
    m_txBypassFlag = sequenceControl0expedited1; // 4.1.2.8.1.2 assign input param to member var for rest of function
    // new ocf
    //klm918 memcpy(m_mapid_ocfData,locfData,MAX_OCF_LENGTH);
    //klm918 m_mapid_ocfLength = locfLen;
    // new frame counter octets
    m_mapid_frameCounterOctets = m_myVcidParent->getVcFrameCounterOctets(m_txBypassFlag); // from here on the frame count octets doesn't change
    lmaxTfdfLen = m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR - m_mapid_frameCounterOctets; // new value for new fco
    //
    ////////////////////////////////////////////////////////////////////////////////////
    // 
    //  handle "add this packet to the txAssemblyBuffer" situation
    // 
    ////////////////////////////////////////////////////////////////////////////////////
    while ( lcopyFromInputIndex < totalInputBytes ) // haven't copied the whole input packet yet
    {
        int inputBytesLeftToCopy = totalInputBytes - lcopyFromInputIndex;
        //
        // get ocf info every time you add a portion to a TFDF - either a new ocf may have appeared or this one may have reached its delivery quota and gone away
        //
        lroomLeftInOutput = lmaxTfdfLen - m_copyToOutputIndex;
        int howMuchToCopy;

        if (inputBytesLeftToCopy <= lroomLeftInOutput ) // it will all fit 
        {
            howMuchToCopy = inputBytesLeftToCopy; // packet ends
        } 
        else 
        {
            howMuchToCopy = lroomLeftInOutput; // packet continues
        }
        //
        // copy and move pointers and set flags
        //
        memcpy(&m_TxAssemblyBuf [ m_copyToOutputIndex ],&inputPacket[lcopyFromInputIndex],howMuchToCopy); // copy the right amount
        //
        // just copied. deduce what you just copied this time (flags reset on transmit
        //
        if ( lcopyFromInputIndex == 0 )  // STARTED, did you end? 
        {
            if ( howMuchToCopy == totalInputBytes ) // started, didn't end
            {
                m_completeInbuf = true; // COPIED A COMPLETE INBUF
                if ( m_fixedlen )
                {
                    if (m_ccsdsPacket)  // PACKET
                    {
                        if ( m_mapfhplvo == NO_VALUE  || m_mapfhplvo == ALL_ONES ) // first pkt in empty txasmbuf or first packet after endspan
                        {
                            m_mapfhplvo = m_copyToOutputIndex; // first octet is FHP
                        }
                    }
                    else // MAPA 
                    {
                        m_mapfhplvo = m_copyToOutputIndex + howMuchToCopy - 1; // LVO =  last valid octet
                    }
                }
            } 
            else   // started, didn't end
            {
                m_beginSpan = true; // COPIED A BEGINNING SPAN
                if ( m_fixedlen )
                {
                    if ( m_ccsdsPacket )
                    {
                        if ( m_mapfhplvo == NO_VALUE || m_mapfhplvo == ALL_ONES)
                        {
                            m_mapfhplvo = m_copyToOutputIndex; // first octet is FHP
                        }
                    }
                    else // MAPA_SDU
                    {
                        m_mapfhplvo = ALL_ONES; // MAPA sdu does not end in this frame
                    }
                }
                // do nothing if variable frame len
            }
        } 
        else  // didn't start at beginning
        {
            if ( lcopyFromInputIndex + howMuchToCopy == totalInputBytes ) { // middle/endspan, did you end? 
                m_endSpan = true;
                if ( m_fixedlen ) 
                {
                    if ( m_ccsdsPacket )
                    {
                        m_mapfhplvo = ALL_ONES ; // no packet started in this tfdf
                    }
                    else // MAPA_SDU
                    {
                        m_mapfhplvo = m_copyToOutputIndex + howMuchToCopy - 1; // LVO = last valid octet
                    }
                }
                // do nothing if variable framelen
            } else {
                m_middleSpan = true;
                if ( m_fixedlen ) 
                {
                    if ( m_ccsdsPacket )
                    {
                        m_mapfhplvo = ALL_ONES; // packet does not end
                    }
                    else // if ( MAPA_SDU )
                    {
                        m_mapfhplvo = ALL_ONES; // MAPA SDU does not begin
                    }
                }
            }
        }
        //
        // now move indexes for next time
        //
        m_copyToOutputIndex += howMuchToCopy;
        lcopyFromInputIndex += howMuchToCopy;

        //
        // handle just-filled buffer
        //
        if ( m_copyToOutputIndex == lmaxTfdfLen ) // just filled buffer. set construction rules based on what's in the buffer
        {
            if ( m_fixedlen) 
            { 
                if ( m_ccsdsPacket )  // PACKET - everything fixedlen is CR_000_SPANNING_DATA_UNITS
                {
                    m_constRules = CR_000_SPANNING_DATA_UNITS;
                } 
                else // MAPA SDU 
                {
                    if ( m_completeInbuf || m_beginSpan )
                    {
                        m_constRules = CR_001_MAPA_SDU_STARTS_MAY_END ;
                    }
                    else if ( m_middleSpan || m_endSpan )
                    {
                        m_constRules = CR_010_CONTINUING_MAPA_SDU_MAY_END ;
                    }
                }
            } 
            else // VARLEN
            {
                if ( m_beginSpan )
                {
                    m_constRules = CR_100_UNFINISHED_SEGMENT_STARTS ;
                }
                else if ( m_middleSpan )
                {
                    m_constRules = CR_101_UNFINISHED_SEGMENT_CONTINUES ;
                }
                else if ( m_endSpan )
                {
                    m_constRules = CR_110_CONTINUED_SEGMENT_ENDS ;
                }
                else if ( m_completeInbuf )
                {
                    m_constRules = CR_111_SEGMENT_STARTS_AND_ENDS ;
                }
            }
            // now have constRules, m_fhp/m_lvo, and full buffer - tx and reset flags
            goodappend = TXtoQueue(m_txBypassFlag, " <--- full m_TxAssemblyBuf ");
        }
    }
    ////////////////////////////////////////////////////////////////////////////////////
    // 
    // 
    //  handle "something left in the buffer after the addition of this packet" situation
    //  if left in buffer it will have been added with a view towards the OCF's presence/absence
    // 
    // 
    ////////////////////////////////////////////////////////////////////////////////////
    if ( m_copyToOutputIndex > 0 ) // SOMETHING is left in the buffer (either an end span or a complete packet; in any case it was added WITH the correct OCF)
    {
        if ( m_endSpan  ) // if what is left over is a PARTIAL (as opposed to one or more complete packets)
        {
            m_txBufStartsWithContinuation = true; // anything left after add-this-packet is a continuation; tx() will clear this if it gets called
        }
        lroomLeftInOutput = lmaxTfdfLen - m_copyToOutputIndex;
        //klmprintf("LEFTOVER: ");
        //see_m_TxAssemblyBuf();
        //klmprintf("\n");fflush(stdout);

        if ( m_ccsdsPacket ) // PACKET 
        {
            if ( m_fixedlen ) // fixed len, something left in buffer. set CONSTRUCTION RULES now, whether or not you tx
            {
                m_constRules = CR_000_SPANNING_DATA_UNITS; // if it's LEFT here, it didn't fill anything. it's either a complete packet or an END span.
            }
            else // variable len
            {
                if ( m_endSpan ) // if END span 
                {
                    m_constRules = CR_110_CONTINUED_SEGMENT_ENDS;
                    // no fhp/lvo in variable len frame
                    // no idle fill in variable length idleFillHere ( &m_TxAssemblyBuf[m_copyToOutputIndex], lroomLeftInOutput );
                    goodappend = TXtoQueue(m_txBypassFlag, " <--- packet leftover endspan ");
                } 
                // if complete packet in buffer, leave it in case there's room for another complete packet in variable buffer. 
                //  packet will be transmitted either when filled, or timed out.
                else if ( m_completeInbuf ) // if complete packet in variable length bufer
                {
                    m_constRules = CR_111_SEGMENT_STARTS_AND_ENDS;
                    // no fhp/lvo in variable len frame
                    // no idle fill in variable length idleFillHere ( &m_TxAssemblyBuf[m_copyToOutputIndex], lroomLeftInOutput );
                    // no tx2queue if variable/packet (mapa sdu can ONLY have one sdu per variable frame)  - another packet may fit. 
                } 
                // only do something with end span since beginSpan,middleSpan will have been txed by while() above and complete packets can be accumulated in variable frames
            }
        }
        else // MAPA_SDU
        {
            if ( m_fixedlen ) // FIXED LEN with leftover in it
            { // won't be a begin span because a begin span would have filled the txasmbuf and been txed in above while loop
                if ( m_completeInbuf ) // complete mapa sdu
                {
                    m_constRules = CR_001_MAPA_SDU_STARTS_MAY_END;
                } 
                else if ( m_endSpan )  // what's leftover is a mapa sdu end span
                {
                    m_constRules = CR_010_CONTINUING_MAPA_SDU_MAY_END;
                }
                m_mapfhplvo = m_copyToOutputIndex - 1; // point at last valid octet
                idleFillHere ( &m_TxAssemblyBuf[m_copyToOutputIndex], lroomLeftInOutput, m_map_pcOidData ); // ok to idle fill fixedlen - LVO says the end of SDU
                m_copyToOutputIndex += lroomLeftInOutput; // move index to reflect new data in tx asm buf
                goodappend = TXtoQueue(m_txBypassFlag, " <--- MAPA complete/endspan leftover");
            }
            else // VARIABLE LEN frame with leftover in it
            {
                if ( m_endSpan )  // if endSpan - actually it will be an endspan regardless - why is this even here
                {
                    m_constRules = CR_110_CONTINUED_SEGMENT_ENDS;
                    // no fhp/lvo in variable len frame
                    // NO IDLE FILL in variable frame for SU - no way for receiver to know end of sdu
                    goodappend = TXtoQueue(m_txBypassFlag, " <--- mapaSdu leftover endspan ");
                }
                // if complete mapa_sdu in buffer, transmit it - there can only be one mapa_sdu in a variable length bufer
                //  packet will be transmitted either when filled, or timed out.
                else if ( m_completeInbuf ) // if ONE mapa_sdu that didn't fill the buffer when added originally is leftover, tx it. can't accumulate mapa sdus
                {
                    m_constRules = CR_111_SEGMENT_STARTS_AND_ENDS;
                    // no fhp/lvo in variable len frame
                    // NO IDLE FILL in variable frame for SU - no way for receiver to know end of sdu
                    // complete mapa sdu - can ONLY be ONE complete mapa sdu in variable length frame (4.1.4.2.2.14)
                    goodappend = TXtoQueue(m_txBypassFlag, " <--- mapaSdu leftover ONE complete MAPA SDU");
                }
                // begin span, middle span will have already been transmitted in while() loop above
            }
        }
        // if anything is STILL left untxd in the datafield and you haven't already started your "max wait until empty tfdf" timer, START it.
        // if you HAVE already started your "max wait until time to empty a started tfdf" timer, and you just added something NEW to the buffer but it's still not full, klmhere
        // any call to tx() below will clear it.
        //
        //
        //
        if ( m_usTimeToTransmitStartedTfdf == FOREVER_IN_THE_FUTURE ) // haven't already started your "max wait until empty tfdf" timer
        {
            // m_usTimeToTransmitStartedTfdf = globalUsTimeNow + (long long)(m_map_maxMsDelayToReleaseTfdfOnceStarted_fromvc * 1000); // any subsequent call to tx() will reset timer
            // klmprintf(" timeToTx unfinished tfdf calcd to be %d\n", (((int)(m_usTimeToTransmitStartedTfdf / 1000000)) - startSecs));	
            m_usTimeToTransmitStartedTfdf = globalUsTimeNow + (long long)(m_map_maxMsDelayToReleaseTfdfOnceStarted_fromvc); // any subsequent call to tx() will reset timer
            klmprintf(" timeToTx unfinished tfdf calcd to be %d\n", (int)m_usTimeToTransmitStartedTfdf);	
        }
    }
    else // NOTHING left in TX buffer - everything has been transmitted, reset ms-until-tx-started-txbuf timer
    {
        m_usTimeToTransmitStartedTfdf = FOREVER_IN_THE_FUTURE;
    }
    if ( sequenceControl0expedited1 == eSequenceControlled )
    {
        m_qSeqCtrlTfdfs_mutex.unlock();
    }
    else
    {
        m_qExpeditedTfdfs_mutex.unlock();
    }
    klmprintf("klm out m_copyToOutputIndex = %d m_constRules = %d\n",m_copyToOutputIndex,m_constRules);fflush(stdout);
    return goodappend;
}
//
// async ocf delivery/retrieval/count problem
// 
// ocfservice assigns ABCD (for 3 frame delivery)
// getOcf retrieves ABCD
// txframe<ABCD> 
// decrement vcid ocf ABCD (now leaves 2 frame delivery)
// getOcf retrieves ABCD
// ocfservice assigns WXYZ (for 3 frame delivery)
// txframe<ABCD> 
// decrement vcid ocf would decrement wxyz.
//
//
bool kmapid::newKlmAddPacketSduTo_FIFO_Tx ( unsigned char *inputPacket, int totalInputBytes, int pvn, int sequenceControl0expedited1, bool realtime)
{
    //
    //
    //  may hafta do some wierd stuff with stuff that's in there NOW before adding this, namely 
    //    tx if new OCF arrives that WON'T fit (tx current non-ocf frame)
    //    tx if new OCF arrives that will fit (add ocf and dec its count)
    //    tx if new inputPacket won't fit (if varlen frame)
    // 	  tx if new Qos var&fixed
    //

    bool goodappend = true;
    /*
       int lroomLeftInOutput; // running total of octets left in transmit assembly buffer
       m_qSeqCtrlTfdfs_mutex.lock();
    // called by packet and MAPA_sdu
    if ( m_ccsdsPacket ) // only check pvns for packet
    {
    if ( packetInfoMib.m_Valid_Packet_Version_Numbers[pvn] == false)
    {
    m_qSeqCtrlTfdfs_mutex.unlock(); // early return - unlock mutex
    return false;
    }
    }

    int lcopyFromInputIndex = 0; // where to start copying from

    ////////////////////////////////////////////////////////////////////////////////////
    // get local latest copy of ocf in case new one has arrived since last time through here OR current one has already been sent enough times (will return 0 length)
    ////////////////////////////////////////////////////////////////////////////////////
    int locfLen;
    unsigned char locfData[MAX_OCF_LENGTH]; 
    m_myVcidParent->getVcidOcfBuf(locfData,&locfLen); // check to see if new OCF has arrived 
    m_mapid_frameCounterOctets = m_myVcidParent->getVcFrameCounterOctets(m_txBypassFlag);  // current frame count counter octets based on current bypass flag

    ////////////////////////////////////////////////////////////////////////////////////
    // handle "something already in the buffer" situation (either packet endspan (fixedlen) or complete packet (varlen) which can have another complete packet added to it)
    ///////////////////////////////////////////////////////////////////////////////////

    if ( m_copyToOutputIndex > 0 ) // something already in buffer before addition
    {
    // two situations where you hafta empty the tx buffer 
    //  - you just got an OCF that won't fit when there was none before (varlen only) OR
    //  - you have a QoS (sequenceControl0expedited1) that's different than the current one (fixed or varlen) OR
    //  - this recently-delivered packet/sdu won't fit (fixed or varlen) or 
    //
    // no current ocf, just got a new one
    //
    // FIRST handle the situation where there is a new OCF that won't fit or JUST fits
    if ( locfLen != 0 && m_mapid_ocfLength == 0 )  // new ocf (is one now, wasn't one before)
    {
    //
    // only an issue if we're variable length and what's in there now is either 4 octets from the end (will hold the new ocf - add and tx this whatcha got now) or less (don't add ocf - just tx whatcha got now, put ocf in next frame)
    //
    if ( !m_fixedlen ) // must be variable (fixedlen always has ocf or always doesn't have ocf)
    {
    // see how much room there is with this new ocf
    lroomLeftInOutput = m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets - m_mapid_frameCounterOctets - locfLen - m_copyToOutputIndex; // total octets available in the tx assembly buffer
    //
    // varlen and now there's JUST enough room for the new ocf
    //
    if ( lroomLeftInOutput == 0 ) 
    {
    // either segmented or unsegmented const rule already in place
    // no need for fhp in varlen
    // no need for idle fill in varlen
    // copy new ocf
    memcpy(m_mapid_ocfData,locfData,MAX_OCF_LENGTH);
    m_mapid_ocfLength = locfLen;
    TX(" <--- somethingInBufBeforeCopy varlen just room for NEW ocf");  
    m_myVcidParent->decrementMCidOcfDeliveryCount(); // decrement the delivery count of the OCF since you just delivered it
    m_txBypassFlag = sequenceControl0expedited1;  // just emptied this frame, save bypass flag in member variable so next comparison won't retransmit an empty frame
    }
    //
    // varlen and now there's NOT enough room for the new ocf
    //
    else if ( lroomLeftInOutput < 0 ) // NO room for new ocf - tx what's in there now
    {
    // tx what's in there now using existing construction rule
    // no need for fhp in varlen
    // no need for idle fill in varlen
    TX(" <--- somethingInBufBeforeCopy varlen *NO* room for NEW ocf");  // DID NOT DELIVER OCF - do not decrement count
    // DID NOT DELIVER OCF - do not decrement count
    m_txBypassFlag = sequenceControl0expedited1;  // just emptied this frame, save bypass flag in member variable so next comparison won't retransmit an empty frame
}
// else there's room for new ocf and at least one octet. if fixedlen it'll span, if varlen the below code will tx existing frame and insert delivered into NEXT frame
}
// else fixedlen - no issue since fixedlen will have constant ocf len (0 or max_ocf_len). ocf doesn't change or expire in fixedlen
}
//
// SECOND, here the ocf WILL fit but if variable length you hafta tx the frame if the NEWLY-DELIVERED PACKET (or sdu) won't fit completely
//
if ( !m_fixedlen ) // only check for will-this-new-packet-fit-if-not-then-tx in variable frame
{
    // get new ocf - may have expired with last tx
    m_myVcidParent->getVcidOcfBuf(m_mapid_ocfData,&m_mapid_ocfLength);
    // how much room is left with this ocf
    lroomLeftInOutput = m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets - m_mapid_ocfLength - m_mapid_frameCounterOctets - m_copyToOutputIndex; // use last datafieldOctets value before assigning new one
    if (lroomLeftInOutput < totalInputBytes ) // if new packet/sdu won't fit COMPLETELY in existing room, tx what's in there already
    {
        // tx what's in there with the new ocf and current bypass flag
        TX(" <--- somethingInBufBeforeCopy, new pkt won't fit in varlen frame");  
        m_myVcidParent->decrementMCidOcfDeliveryCount(); // decrement the delivery count of the OCF since you just delivered it
        m_txBypassFlag = sequenceControl0expedited1;  // just emptied this frame, save bypass flag in member variable so next comparison won't retransmit an empty frame
    }
}
//
// THIRD handle the situation where QoS (bypass flag) changes (so you use different frame counters and possibly different frame counter octets
// may still be stuff in frame; if bypass flag is new, empty frame and start new frame with new SDU
//
if (m_txBypassFlag != sequenceControl0expedited1 )  // in either fixed or variable length frame, NEW QoS means new frame. if fixed len, idle fill, else tx as is
{
    // having proven the ocf will FIT (or handled the where it won't) send the new ocf in this frame
    memcpy(m_mapid_ocfData,locfData,MAX_OCF_LENGTH);  // guaranteed newocf will fit, if you hafta do something, copy it into the new frame
    m_mapid_ocfLength = locfLen; 	// this ocf len
    // tx what's in there now using existing construction rule, existing ocf len, and existing frame counter octets
    if ( m_fixedlen ) // idle fill if fixedlen 
    {
        m_mapfhplvo = m_copyToOutputIndex; // first octet is FHP
        lroomLeftInOutput = m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets - m_mapid_ocfLength - m_mapid_frameCounterOctets - m_copyToOutputIndex; // use last datafieldOctets value before assigning new one
        idleFillHere ( &m_TxAssemblyBuf[m_copyToOutputIndex], lroomLeftInOutput, m_map_pcOidData ); // ok to idle fill fixedlen - LVO says the end of SDU
        m_copyToOutputIndex += lroomLeftInOutput; // move index to reflect new data in tx asm buf
    }
    // else varlen - leave as is.
    TX(" <--- somethingInBufBeforeCopy, packet, NEW QoS ");  
    m_myVcidParent->decrementMCidOcfDeliveryCount(); // decrement the delivery count of the OCF since you just delivered it
}
}
//
// now done every exceptional thing, deal with NEW ocf, NEW bypass flag, and NEW packet/sdu
//
// new QoS
m_txBypassFlag = sequenceControl0expedited1; // 4.1.2.8.1.2 assign input param to member var for rest of function
// new ocf
memcpy(m_mapid_ocfData,locfData,MAX_OCF_LENGTH);
m_mapid_ocfLength = locfLen;
// new frame counter octets
m_mapid_frameCounterOctets = m_myVcidParent->getVcFrameCounterOctets(m_txBypassFlag); // from here on the frame count octets doesn't change
//
////////////////////////////////////////////////////////////////////////////////////
// 
//  handle "add this packet to the txAssemblyBuffer" situation
// 
////////////////////////////////////////////////////////////////////////////////////
while ( lcopyFromInputIndex < totalInputBytes ) // haven't copied the whole input packet yet
{
    int inputBytesLeftToCopy = totalInputBytes - lcopyFromInputIndex;
    //
    // get ocf info every time you add a portion to a TFDF - either a new ocf may have appeared or this one may have reached its delivery quota and gone away
    //
    m_myVcidParent->getVcidOcfBuf(m_mapid_ocfData,&m_mapid_ocfLength);
    lroomLeftInOutput = m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets - m_mapid_ocfLength - m_mapid_frameCounterOctets - m_copyToOutputIndex;
    int howMuchToCopy;

    if (inputBytesLeftToCopy <= lroomLeftInOutput ) // it will all fit 
    {
        howMuchToCopy = inputBytesLeftToCopy; // packet ends
    } 
    else 
    {
        howMuchToCopy = lroomLeftInOutput; // packet continues
    }
    //
    // copy and move pointers and set flags
    //
    memcpy(&m_TxAssemblyBuf [ m_copyToOutputIndex ],&inputPacket[lcopyFromInputIndex],howMuchToCopy); // copy the right amount
    //
    // just copied. deduce what you just copied this time (flags reset on transmit
    //
    if ( lcopyFromInputIndex == 0 )  // STARTED, did you end? 
    {
        if ( howMuchToCopy == totalInputBytes ) // started, didn't end
        {
            m_completeInbuf = true; // COPIED A COMPLETE INBUF
            if ( m_fixedlen )
            {
                if (m_ccsdsPacket)  // PACKET
                {
                    if ( m_mapfhplvo == NO_VALUE  || m_mapfhplvo == ALL_ONES ) // first pkt in empty txasmbuf or first packet after endspan
                    {
                        m_mapfhplvo = m_copyToOutputIndex; // first octet is FHP
                    }
                }
                else // MAPA 
                {
                    m_mapfhplvo = m_copyToOutputIndex + howMuchToCopy - 1; // LVO =  last valid octet
                }
            }
        } 
        else   // started, didn't end
        {
            m_beginSpan = true; // COPIED A BEGINNING SPAN
            if ( m_fixedlen )
            {
                if ( m_ccsdsPacket )
                {
                    if ( m_mapfhplvo == NO_VALUE || m_mapfhplvo == ALL_ONES)
                    {
                        m_mapfhplvo = m_copyToOutputIndex; // first octet is FHP
                    }
                }
                else // MAPA_SDU
                {
                    m_mapfhplvo = ALL_ONES; // MAPA sdu does not end in this frame
                }
            }
            // do nothing if variable frame len
        }
    } 
    else  // didn't start at beginning
    {
        if ( lcopyFromInputIndex + howMuchToCopy == totalInputBytes ) { // middle/endspan, did you end? 
            m_endSpan = true;
            if ( m_fixedlen ) 
            {
                if ( m_ccsdsPacket )
                {
                    m_mapfhplvo = ALL_ONES ; // no packet started in this tfdf
                }
                else // MAPA_SDU
                {
                    m_mapfhplvo = m_copyToOutputIndex + howMuchToCopy - 1; // LVO = last valid octet
                }
            }
            // do nothing if variable framelen
        } else {
            m_middleSpan = true;
            if ( m_fixedlen ) 
            {
                if ( m_ccsdsPacket )
                {
                    m_mapfhplvo = ALL_ONES; // packet does not end
                }
                else // if ( MAPA_SDU )
                {
                    m_mapfhplvo = ALL_ONES; // MAPA SDU does not begin
                }
            }
        }
    }
    //
    // now move indexes for next time
    //
    m_copyToOutputIndex += howMuchToCopy;
    lcopyFromInputIndex += howMuchToCopy;

    //
    // handle just-filled buffer
    //
    if ( m_copyToOutputIndex == (m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets - m_mapid_ocfLength - m_mapid_frameCounterOctets ) ) // just filled buffer. set construction rules based on what's in the buffer
    {
        if ( m_fixedlen) 
        { 
            if ( m_ccsdsPacket )  // PACKET - everything fixedlen is CR_000_SPANNING_DATA_UNITS
            {
                m_constRules = CR_000_SPANNING_DATA_UNITS;
            } 
            else // MAPA SDU 
            {
                if ( m_completeInbuf || m_beginSpan )
                {
                    m_constRules = CR_001_MAPA_SDU_STARTS_MAY_END ;
                }
                else if ( m_middleSpan || m_endSpan )
                {
                    m_constRules = CR_010_CONTINUING_MAPA_SDU_MAY_END ;
                }
            }
        } 
        else // VARLEN
        {
            if ( m_beginSpan )
            {
                m_constRules = CR_100_UNFINISHED_SEGMENT_STARTS ;
            }
            else if ( m_middleSpan )
            {
                m_constRules = CR_101_UNFINISHED_SEGMENT_CONTINUES ;
            }
            else if ( m_endSpan )
            {
                m_constRules = CR_110_CONTINUED_SEGMENT_ENDS ;
            }
            else if ( m_completeInbuf )
            {
                m_constRules = CR_111_SEGMENT_STARTS_AND_ENDS ;
            }
        }
        // now have constRules, m_fhp/m_lvo, and full buffer - tx and reset flags
        TX(" <--- full m_TxAssemblyBuf ");
        m_myVcidParent->decrementMCidOcfDeliveryCount(); // decrement the delivery count of the OCF since you just delivered it
    }
}
////////////////////////////////////////////////////////////////////////////////////
// 
// 
//  handle "something left in the buffer after the addition of this packet" situation
//  if left in buffer it will have been added with a view towards the OCF's presence/absence
// 
// 
////////////////////////////////////////////////////////////////////////////////////
if ( m_copyToOutputIndex > 0 ) // SOMETHING is left in the buffer (either an end span or a complete packet; in any case it was added WITH the correct OCF)
{
    //
    // get ocf info every time you add a portion to a TFDF - either a new ocf may have appeared or this one may have reached its delivery quota and gone away
    //
    m_myVcidParent->getVcidOcfBuf(m_mapid_ocfData,&m_mapid_ocfLength);
    if ( m_endSpan  ) // if what is left over is a PARTIAL (as opposed to one or more complete packets)
    {
        m_txBufStartsWithContinuation = true; // anything left after add-this-packet is a continuation; tx() will clear this if it gets called
    }
    lroomLeftInOutput = m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets - m_mapid_ocfLength - m_mapid_frameCounterOctets - m_copyToOutputIndex;
    //klmprintf("LEFTOVER: ");
    //see_m_TxAssemblyBuf();
    //klmprintf("\n");fflush(stdout);

    if ( m_ccsdsPacket ) // PACKET 
    {
        if ( ! m_fixedlen ) // variable len
        {
            if ( m_endSpan ) // if END span 
            {
                m_constRules = CR_110_CONTINUED_SEGMENT_ENDS;
                // no fhp/lvo in variable len frame
                // no idle fill in variable length idleFillHere ( &m_TxAssemblyBuf[m_copyToOutputIndex], lroomLeftInOutput );
                TX(" <--- packet leftover endspan ");
                m_myVcidParent->decrementMCidOcfDeliveryCount(); // decrement the delivery count of the OCF since you just delivered it
            } 
            // if complete packet in buffer, leave it in case there's room for another complete packet in variable buffer. 
            //  packet will be transmitted either when filled, or timed out.
            //else if ( m_completeInbuf ) // if complete packet in variable length bufer
            //{
            //	m_constRules = CR_111_SEGMENT_STARTS_AND_ENDS;
            //	// no fhp/lvo in variable len frame
            //	// no idle fill in variable length idleFillHere ( &m_TxAssemblyBuf[m_copyToOutputIndex], lroomLeftInOutput );
            //	TX(" <--- complete packet leftover  ");
            //} 
            // only do something with end span since beginSpan,middleSpan will have been txed by while() above and complete packets can be accumulated in variable frames
        }
    }
    else // MAPA_SDU
    {
        if ( m_fixedlen ) // FIXED LEN with leftover in it
        { // won't be a begin span because a begin span would have filled the txasmbuf and been txed in above while loop
            if ( m_completeInbuf ) // complete mapa sdu
            {
                m_constRules = CR_001_MAPA_SDU_STARTS_MAY_END;
            } 
            else if ( m_endSpan )  // what's leftover is a mapa sdu end span
            {
                m_constRules = CR_010_CONTINUING_MAPA_SDU_MAY_END;
            }
            m_mapfhplvo = m_copyToOutputIndex - 1; // point at last valid octet
            idleFillHere ( &m_TxAssemblyBuf[m_copyToOutputIndex], lroomLeftInOutput, m_map_pcOidData ); // ok to idle fill fixedlen - LVO says the end of SDU
            m_copyToOutputIndex += lroomLeftInOutput; // move index to reflect new data in tx asm buf
            TX(" <--- MAPA complete/endspan leftover");
            m_myVcidParent->decrementMCidOcfDeliveryCount(); // decrement the delivery count of the OCF since you just delivered it
        }
        else // VARIABLE LEN frame with leftover in it
        {
            if ( m_endSpan )  // if endSpan - actually it will be an endspan regardless - why is this even here
            {
                m_constRules = CR_110_CONTINUED_SEGMENT_ENDS;
                // no fhp/lvo in variable len frame
                // NO IDLE FILL in variable frame for SU - no way for receiver to know end of sdu
                TX(" <--- mapaSdu leftover endspan ");
                m_myVcidParent->decrementMCidOcfDeliveryCount(); // decrement the delivery count of the OCF since you just delivered it
            }
            // if complete mapa_sdu in buffer, leave it in case there's room for another complete packet in variable buffer. 
            //  packet will be transmitted either when filled, or timed out.
            // else if ( m_completeInbuf ) // if ONE mapa_sdu that didn't fill the buffer when added originally is leftover, tx it. can't accumulate mapa sdus
            // {
            // 	m_constRules = CR_111_SEGMENT_STARTS_AND_ENDS;
            // 	// no fhp/lvo in variable len frame
            // 	// NO IDLE FILL in variable frame for SU - no way for receiver to know end of sdu
            // 	TX(" <--- mapaSdu leftover ONE complete MAPA SDU");
            // }
            // begin span, middle span will have already been transmitted in while() loop above
        }
    }
    // if anything is STILL left untxd in the datafield and you haven't already started your "max wait until empty tfdf" timer, START it.
    // any call to tx() below will clear it.
    if ( m_usTimeToTransmitStartedTfdf == FOREVER_IN_THE_FUTURE ) // haven't already started your "max wait until empty tfdf" timer
    {
        // m_usTimeToTransmitStartedTfdf = globalUsTimeNow + (long long)(m_map_maxMsDelayToReleaseTfdfOnceStarted_fromvc * 1000); // any subsequent call to tx() will reset timer
        // klmprintf(" timeToTx unfinished tfdf calcd to be %d\n", (((int)(m_usTimeToTransmitStartedTfdf / 1000000)) - startSecs));	
        m_usTimeToTransmitStartedTfdf = globalUsTimeNow + (long long)(m_map_maxMsDelayToReleaseTfdfOnceStarted_fromvc); // any subsequent call to tx() will reset timer
        klmprintf(" timeToTx unfinished tfdf calcd to be %d\n", (int)(m_usTimeToTransmitStartedTfdf));	
    }
}
m_qSeqCtrlTfdfs_mutex.unlock();
*/
return goodappend;
}
bool kmapid::newKlmAddOctetStreamTo_QUEUE_Tx( unsigned char *inputPacket, int inputLen/* 2/21/2018 4:25pm greg kazz email removes this , int sequenceControl0expedited1*/)
{
    //
    // UNLIKE PACKET DATA or MAPA_SDU data, octet stream data is sent immediately, in one variable length frame or spanning several frames all of which are sent immediately
    //
    // regarding: Frame Count octets
    //
    // allow for changing frame count octets (QoS of either 'sequence Controlled' or 'expedited'). 
    // can't span an octet stream over changing QoS
    // then again, octet stream, unlike map packets or mapa sdus, won't have parts left in buffers for later.
    // SO YOU DON'T HAFTA WORRY ABOUT "if the QoS changes, tx what's in there now, then change the QoS for THIS addition"
    //
    // still, to use the same code, be sure m_txBypassFlag is set so TXtoQueue includes the one-octet qos indicator in the bufs you add to the queue
    //

    m_txBypassFlag = 1; /* 2/21/2018 4:25pm greg kazz email removes parameter. hardcoding to EXPEDITED becuase the email said "Supporting the sequence controlled service implies quite some work on the provider and also on the user"*/; // 4.1.2.8.1.2 //2018 08 22 if you're gonna hardcode something, hardcode it BEFORE any code that uses it. duh.
    bool goodappend = true;
    int lroomLeftInOutput; // running total of octets left in transmit assembly buffer
    m_mapid_frameCounterOctets = m_myVcidParent->getVcFrameCounterOctets(m_txBypassFlag);  // current frame count counter octets based on CURRENT QoS flag
    int lmaxTfdfLen = m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR - m_mapid_frameCounterOctets; // find real max len allowing for seq/exp fco

    m_qSeqCtrlTfdfs_mutex.lock(); // octet stream always uses seqCtrl bypass flag as per 2/21/2018 4:25 greg kazz email
    if ( m_fixedlen ) // NO OCTET STREAM if fixed length
    {
        m_qSeqCtrlTfdfs_mutex.unlock(); // octet stream always uses seqCtrl bypass flag as per 2/21/2018 4:25 greg kazz email
        return false;
    }
    // since queue and tx assembly buf share a mutex (writer and reader could fill/empty both)

    m_txBufStartsWithContinuation = false; // since sending SDU at a time per addMapaSduData() call, we'll always start with a starting datafield

    // get local copy of Frame Counter Octets
    m_mapid_frameCounterOctets = m_myVcidParent->getVcFrameCounterOctets(m_txBypassFlag);  // current frame count counter octets based on current bypass flag
    // get ocf into m_map_members
    // no need to get ocf info for queues m_myVcidParent->getVcidOcfBuf(m_mapid_ocfData,&m_mapid_ocfLength);

    // in this case m_fhplvo means last valid octet. point to end after every add
    // build octet stream header once
    //mbf.putAddr(m_permapheader);
    //mbf.put(0,3,CR_011_OCTET_STREAM); // set octet stream construction rules
    // --- directly AND/OR in the construction rule
    m_permapheader[0] &= 0x1f; // AND out the top 3 bits
    m_permapheader[0] |= OR_CR_011_OCTET_STREAM; // OR in the correct bits; UPID ALREADY ORd IN from managed parameter MAP_CHANNEL_USLP_Protocol_ID_Supported in readMibConfig

    int lcopyFromInputIndex = 0;

    // there will never be anything 'already in' the buffer. octet stream data is transmitted immediately. if it spans, the spanned frame is transmitted immediately

    while (lcopyFromInputIndex < inputLen )
    {
        int linputBytesLeftToCopy = inputLen - lcopyFromInputIndex;
        //
        // find how much room there is left in the frame.
        //   this depends on Frame Count octets which change, albeit not inside this function // no ocf accounting if writing to queues and OCF (which may or may not be present)
        //
        lroomLeftInOutput = lmaxTfdfLen - m_copyToOutputIndex;

        //
        // endbyteIndex - dataSoFarIndex
        //
        int lhowMuchToCopy;
        if (linputBytesLeftToCopy <= lroomLeftInOutput ) // it will all fit 
        {
            lhowMuchToCopy = linputBytesLeftToCopy; // packet ends
        }
        else
        {
            lhowMuchToCopy = lroomLeftInOutput; // packet continues
        }
        // copy the right amount
        klmprintf("newklmaddoctetstream2q @%lld copying %d from %d\n",globalUsTimeNow,lhowMuchToCopy, lcopyFromInputIndex);fflush(stdout);
        memcpy( &m_TxAssemblyBuf [ m_copyToOutputIndex ], &inputPacket[ lcopyFromInputIndex ], lhowMuchToCopy);
        // add bytes copied
        m_copyToOutputIndex += lhowMuchToCopy;
        m_mapfhplvo = m_copyToOutputIndex - 1; // last valid octet moves with each packet added
        lcopyFromInputIndex += lhowMuchToCopy;
        if ( m_copyToOutputIndex == lmaxTfdfLen )
        {
            // goodappend = m_qSeqCtrlTfdfs->appendklm ( m_permapheader, m_permapheaderLen, m_TxAssemblyBuf, m_copyToOutputIndex ); // use two-datafield append (copyright 2016 by kevan moore, the awesome)
            // tx here
            m_constRules = CR_011_OCTET_STREAM;
            TXtoQueue(m_txBypassFlag, " <---newKlmAddOctetStreamToQueue full txasmbuf");
            // no ocf done for queues m_myVcidParent->decrementMCidOcfDeliveryCount(); // decrement the delivery count of the OCF since you just delivered it
            // init writing index
            m_copyToOutputIndex = 0;
            if ( lcopyFromInputIndex < inputLen ) // there is still more to copy 
            {
                m_txBufStartsWithContinuation = true; // the next buffer (if we stay in the while()) will be a continuation // here for consistency - but octet stream doesn't have 'continuation' packets
            }
        }
    }
    // here, some or all of the packet is in the frame.
    if ( m_copyToOutputIndex != 0 ) // if something is left in the buffer
    {
        m_mapfhplvo = m_copyToOutputIndex - 1; // point at byte before first-byte-to-write as last valid octet
        if ( m_usTimeToTransmitStartedTfdf == FOREVER_IN_THE_FUTURE ) // if there's not already a time in it
        {
            // m_usTimeToTransmitStartedTfdf = globalUsTimeNow + (long long)(m_map_maxMsDelayToReleaseTfdfOnceStarted_fromvc * 1000); // find time when you hafta tx tfdf after you start filling it
            m_usTimeToTransmitStartedTfdf = globalUsTimeNow + (long long)(m_map_maxMsDelayToReleaseTfdfOnceStarted_fromvc); // find time when you hafta tx tfdf after you start filling it
        }
        // since this is a variable length frame, only add the data IN the frame, not the whole available length
        // goodappend = m_qSeqCtrlTfdfs->appendklm ( m_permapheader, m_permapheaderLen, m_TxAssemblyBuf, m_copyToOutputIndex ); // use two-datafield append (copyright 2016 by kevan moore, the awesome)
        // tx here
        m_constRules = CR_011_OCTET_STREAM;
        TXtoQueue(m_txBypassFlag, " <---newKlmAddOctetStreamToQueue leftover txasmbuf");
        // no ocf processing for queues m_myVcidParent->decrementMCidOcfDeliveryCount(); // decrement the delivery count of the OCF since you just delivered it
        // NO NEED TO get possibly new ocf data into m_map_members since it'll be gotten again next time we enter the function
        m_copyToOutputIndex = 0;
        m_usTimeToTransmitStartedTfdf = FOREVER_IN_THE_FUTURE; // reset timer
        m_mapfhplvo = 0;
        m_txBufStartsWithContinuation = false; // the next buffer (if we stay in the while()) will be a continuation
    }
    else // NOTHING left in TX buffer - everything has been transmitted, reset ms-until-tx-started-txbuf timer
    {
        m_usTimeToTransmitStartedTfdf = FOREVER_IN_THE_FUTURE;
    }
    m_qSeqCtrlTfdfs_mutex.unlock(); // octet stream always uses seqCtrl bypass flag as per 2/21/2018 4:25 greg kazz email
    return goodappend;
}
/*bool kmapid::newKlmAddOctetStreamToFifo( unsigned char *inputPacket, int inputLen, int sequenceControl0expedited1)
  {
//
// UNLIKE PACKET DATA or MAPA_SDU data, octet stream data is sent immediately, in one variable length frame or spanning several frames all of which are sent immediately
//
// regarding: Frame Count octets
//
// allow for changing frame count octets (QoS of either 'sequence Controlled' or 'expedited'). 
// can't span an octet stream over changing QoS
// then again, octet stream, unlike map packets or mapa sdus, won't have parts left in buffers for later.
// SO YOU DON'T HAFTA WORRY ABOUT "if the QoS changes, tx what's in there now, then change the QoS for THIS addition"
//

bool goodappend = true;
int lroomLeftInOutput; // running total of octets left in transmit assembly buffer

if ( m_fixedlen ) // NO OCTET STREAM if fixed length
{
return false;
}
// since queue and tx assembly buf share a mutex (writer and reader could fill/empty both)

m_txBypassFlag = sequenceControl0expedited1; // 4.1.2.8.1.2
m_txBufStartsWithContinuation = false; // since sending SDU at a time per addMapaSduData() call, we'll always start with a starting datafield

// get local copy of Frame Counter Octets
m_mapid_frameCounterOctets = m_myVcidParent->getVcFrameCounterOctets(m_txBypassFlag);  // current frame count counter octets based on current bypass flag
// get ocf into m_map_members
m_myVcidParent->getVcidOcfBuf(m_mapid_ocfData,&m_mapid_ocfLength);

// in this case m_fhplvo means last valid octet. point to end after every add
// build octet stream header once
// mbf.putAddr(m_permapheader);
// mbf.put(0,3,CR_011_OCTET_STREAM); // set octet stream construction rules
// --- directly AND/OR in the construction rule
m_permapheader[0] &= 0x1f; // AND out the top 3 bits
m_permapheader[0] |= OR_CR_011_OCTET_STREAM; // OR in the correct bits; UPID ALREADY ORd IN from managed parameter MAP_CHANNEL_USLP_Protocol_ID_Supported in readMibconfig

// 
int lcopyFromInputIndex = 0;

// there will never be anything 'already in' the buffer. octet stream data is transmitted immediately. if it spans, the spanned frame is transmitted immediately

while (lcopyFromInputIndex < inputLen )
{
int linputBytesLeftToCopy = inputLen - lcopyFromInputIndex;
//
// find how much room there is left in the frame.
//   this depends on Frame Count octets (which change, albeit not inside this function) and OCF (which may or may not be present)
//
lroomLeftInOutput = m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets - m_mapid_ocfLength - m_mapid_frameCounterOctets - m_copyToOutputIndex;

//
// endbyteIndex - dataSoFarIndex
//
int lhowMuchToCopy;
if (linputBytesLeftToCopy <= lroomLeftInOutput ) // it will all fit 
{
lhowMuchToCopy = linputBytesLeftToCopy; // packet ends
}
else
{
lhowMuchToCopy = lroomLeftInOutput; // packet continues
}
// copy the right amount
memcpy( &m_TxAssemblyBuf [ m_copyToOutputIndex ], &inputPacket[ lcopyFromInputIndex ], lhowMuchToCopy);
// add bytes copied
m_copyToOutputIndex += lhowMuchToCopy;
m_mapfhplvo = m_copyToOutputIndex - 1; // last valid octet moves with each packet added
lcopyFromInputIndex += lhowMuchToCopy;
if ( m_copyToOutputIndex == (m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets - m_mapid_ocfLength - m_mapid_frameCounterOctets) )
{
    // goodappend = m_qSeqCtrlTfdfs->appendklm ( m_permapheader, m_permapheaderLen, m_TxAssemblyBuf, m_copyToOutputIndex ); // use two-datafield append (copyright 2016 by kevan moore, the awesome)
    // tx here
    m_constRules = CR_011_OCTET_STREAM;
    TX(" <---newKlmAddOctetStreamToFifo full txasmbuf");
    // klm918 decrementedUponGet() m_myVcidParent->decrementMCidOcfDeliveryCount(); // decrement the delivery count of the OCF since you just delivered it
    // get possibly new ocf data into m_map_members
    m_myVcidParent->getVcidOcfBuf(m_mapid_ocfData,&m_mapid_ocfLength);
    // init writing index
    m_copyToOutputIndex = 0;
    if ( lcopyFromInputIndex < inputLen ) // there is still more to copy 
    {
        m_txBufStartsWithContinuation = true; // the next buffer (if we stay in the while()) will be a continuation
    }
}
}
// here, some or all of the packet is in the frame.
if ( m_copyToOutputIndex != 0 ) // if something is left in the buffer
{
    m_mapfhplvo = m_copyToOutputIndex - 1; // point at byte before first-byte-to-write as last valid octet
    if ( m_usTimeToTransmitStartedTfdf == FOREVER_IN_THE_FUTURE ) // if there's not already a time in it
    {
        // m_usTimeToTransmitStartedTfdf = globalUsTimeNow + (long long)(m_map_maxMsDelayToReleaseTfdfOnceStarted_fromvc * 1000); // find time when you hafta tx tfdf after you start filling it
        m_usTimeToTransmitStartedTfdf = globalUsTimeNow + (long long)(m_map_maxMsDelayToReleaseTfdfOnceStarted_fromvc); // find time when you hafta tx tfdf after you start filling it
    }
    // since this is a variable length frame, only add the data IN the frame, not the whole available length
    // goodappend = m_qSeqCtrlTfdfs->appendklm ( m_permapheader, m_permapheaderLen, m_TxAssemblyBuf, m_copyToOutputIndex ); // use two-datafield append (copyright 2016 by kevan moore, the awesome)
    // tx here
    m_constRules = CR_011_OCTET_STREAM;
    TX(" <---newKlmAddOctetStreamToFifo leftover txasmbuf");
    // klm918 decrementedUponGet() m_myVcidParent->decrementMCidOcfDeliveryCount(); // decrement the delivery count of the OCF since you just delivered it
    // NO NEED TO get possibly new ocf data into m_map_members since it'll be gotten again next time we enter the function
    m_copyToOutputIndex = 0;
    m_mapfhplvo = 0;
    m_txBufStartsWithContinuation = false; // the next buffer (if we stay in the while()) will be a continuation
}
return goodappend;
}
    */
void kmapid::constructPerMapHeader( bool startsWithContinuation, bool continuesToNextFrame, bool isVariableLenFrame, int fhplvoOffset, int fhplvo )
{
#ifndef NEWMAKETFDFHEADER
    bool laddFhpLvo = false; // assume no fhplvo (only add fhplvo on fixed length frames)
#endif // NEWMAKETFDFHEADER
    int constRules;

    ///////////////
    // NOTE THAT THIS IS DONE INSIDE A q LOCK
    ///////////////

    // klmprintf(" startswContin %s conTnF %s isVln %s fhplvoOfst %d fhplvo %d\n",startsWithContinuation?"T":"F",continuesToNextFrame?"T":"F",isVariableLenFrame?"T":"F",fhplvoOffset,fhplvo);fflush(stdout);

    if (!isVariableLenFrame) // if FIXED
    {
#ifndef NEWMAKETFDFHEADER
        laddFhpLvo = true; // all fixed frames need fhp or lvo
#endif // NEWMAKETFDFHEADER
        // either 000 (packet) or (
        if ( m_map_ServiceDataUnitType == eMAP_PACKET ) // fixed packet   000
        {
            constRules = CR_000_SPANNING_DATA_UNITS; // fixed packet is 000
            //klmprintf("constRules = CR_000_SPANNING_DATA_UNITS \n");fflush(stdout);
        }
        else if ( !startsWithContinuation ) // is MAPA_SDU, does it start at 0?
        {
            constRules = CR_001_MAPA_SDU_STARTS_MAY_END;  // starts at 0, mapa sdu = 001
            //klmprintf("constRules = CR_001_MAPA_SDU_STARTS_MAY_END\n");fflush(stdout);
        }
        else // is MAPA_SDU, does not start at 0 (previous packet continues into this one)
        {
            constRules = CR_010_CONTINUING_MAPA_SDU_MAY_END;  // starts later than 1, has continuation stuff in it, mapa_sdu, fixed = 010
            //klmprintf("constRules = CR_010_CONTINUING_MAPA_SDU_MAY_END\n");fflush(stdout);
        }
    }
    else // IS VARIABLE LEN FRAME
    {
        if ( !startsWithContinuation ) // if starts at 0
        {
            if ( continuesToNextFrame ) // doesn't finish
            {
                constRules = CR_100_UNFINISHED_SEGMENT_STARTS; // var, starts at 0, unfinished
                //klmprintf("constRules = CR_100_UNFINISHED_SEGMENT_STARTS\n");fflush(stdout);
            }
            else // starts at 0 and DOES finish 
            {
                constRules = CR_111_SEGMENT_STARTS_AND_ENDS; // var, starts at 0, finished
                //klmprintf("constRules = CR_111_SEGMENT_STARTS_AND_ENDS\n");fflush(stdout);
            }
        }
        else  // IS a continuation frame
        {
            if ( continuesToNextFrame ) // is a continuation frame and doesn't finish
            {
                constRules = CR_101_UNFINISHED_SEGMENT_CONTINUES; // var, continuation frame, unfinished
                //klmprintf("constRules = CR_101_UNFINISHED_SEGMENT_CONTINUES\n");fflush(stdout);
            }
            else // is a continuation frame and DOES finish 
            {
                constRules = CR_110_CONTINUED_SEGMENT_ENDS; // var, starts at 0, finished
                //klmprintf("constRules = CR_110_CONTINUED_SEGMENT_ENDS\n");fflush(stdout);
            }
        }
    }
    m_constRules = constRules;
#ifdef NEWMAKETFDFHEADER
    makeTFDFheader( m_permapheader, constRules, m_map_UslpProtocolIdSupported, fhplvo);
#else
    mbf.putAddr(m_permapheader);
    mbf.put(0,3,constRules); // set octet stream construction rules
    if ( laddFhpLvo )
    {
        // point at fhplvo offset in header
        mbf.putAddr(&m_permapheader[m_fhplvoOffset]);
        mbf.put(0,16,fhplvo); // set octet stream construction rules
    }
#endif // NEWMAKETFDFHEADER
    //
    // kprMutex.lock();printf("frameheader "); seedata(m_permapheader,lheaderlen); printf("\n");fflush(stdout);kprMutex.unlock();
}
//
// add packet to txAssemblyBuf. truncate-and-shove-to-out-queue if too big
//
void kmapid::deliverRawDataFromTruncatedFrame(String &physchan, int mcid, unsigned char *truncatedRawData )
{
    int ldatabytes = m_myVcidParent->m_truncatedFrameTotalLength - 4;

    kprMutex.lock();printf ( "dTu TRU l%2d %s-%6d-%1d-%1d ", ldatabytes, physchan.c_str(), mcid,  m_map_VCID , m_map_MAPID); seedata ( truncatedRawData, ldatabytes ); printf("\n");fflush(stdout);kprMutex.unlock();
}
//
//
//
// getPacketToTx()
// come up with SOMETHING. return partially filled tfdf if ya got one.
//
/*
   bool kmapid::getPacketToTx(unsigned char *retrieveData, int *retrieveDataLen, bool *whatIGotWasQueueData) 
   {
   bool gotSomething = false;
#ifdef NONEEDFORGETPACKETTOTX
//
//
// rewrite this for two queues (exp/sqctrl) if this ever gets uncommented
//
//
int headeredTxAssemblyBufDataLen; // how many octets are in there NOW, counting the header
// if packet svc type, move all pvns to 0
//	try to obtain packet from queue
//	if no packet in queue
//	{
//		get txassemblybuf
//		fill with idle
//		reset fill params
//	}
m_qSeqCtrlTfdfs_mutex.lock();
// check output Queue first
 *retrieveDataLen = m_qSeqCtrlTfdfs->retrieve(retrieveData,*retrieveDataLen);
 if (*retrieveDataLen > 0 ) // data was in queue - retrieve headeredData
 {
 gotSomething = true; // got a packet from queue
 *whatIGotWasQueueData = true;
 klmprintf("getPacketToTx got rdL %d\n",*retrieveDataLen);fflush(stdout);
 }
 else // no data in queue - if any tfdf being built and it's been there too long, get it as is , add header, and idle fill
 {
 if ( m_copyToOutputIndex > 0 ) // something in tx buffer AND past time to transmit it (since it was called by a routine that asks checkForMapData which includes is-it-time-to-transmit queries
 {
 kprMutex.lock();printf("getPacketToTx m_oftswttxb %d getting leftover txsembuf data .....................................",m_copyToOutputIndex);seedata(m_TxAssemblyBuf ,m_copyToOutputIndex);printf("\n");fflush(stdout);kprMutex.unlock();
//
// gotta build a whole packet in retrieveData[] out of leftover tx assembly buf data
// and allow for idle filling (if fixed length)
//
headeredTxAssemblyBufDataLen = m_permapheaderLen + m_copyToOutputIndex;
m_mapfhplvo = m_copyToOutputIndex; // this is where the new idle packet would start
constructPerMapHeader( m_txBufStartsWithContinuation, false, !m_fixedlen  , m_fhplvoOffset, m_mapfhplvo);// !m_fixed since constructPerMapHeader is looking for isVariable flag
klmprintf("kzu m_txBufStartsWithContinuation %d isvarlen %d m_fhplvoOffset %d m_mapfhplvo %d\n", m_txBufStartsWithContinuation, !m_fixedlen, m_fhplvoOffset, m_mapfhplvo);fflush(stdout);
memcpy(retrieveData,m_permapheader,m_permapheaderLen); // copy header
memcpy(&retrieveData[m_permapheaderLen], m_TxAssemblyBuf , m_copyToOutputIndex); // copy headerlessData

// if buffer is not full then fill the rest of the way with idle packet
// since you just put a header onto the headerless leftover data, the fill data needs to be the headerlessLength PLUS header length MINUS what's in there now
klmprintf("before idle fill htxdl = %d room = %d pmhl=%d\n",headeredTxAssemblyBufDataLen, m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets - m_mapid_frameCounterOctets - m_mapid_ocfLength, m_permapheaderLen);fflush(stdout);
//
// when you idle fill you're assuming that what's in the txassemblybuf is the end of a completed unit.
// therefore when you idle fill you set the FHP to point to the start of the idle packet
//
if ( m_fixedlen )
{
int lTotalTfdfLen = m_maxTotalHeaderlessDataFieldOctets + m_permapheaderLen; // this is what the total TFDF len should be (assumes one header and one headerless datafield)
idleFillHere(&retrieveData[ headeredTxAssemblyBufDataLen ], lTotalTfdfLen - headeredTxAssemblyBufDataLen, m_map_pcOidData );  // idlefill until end
 *retrieveDataLen = lTotalTfdfLen;  // since you know you have at least ONE header, include the header in the returned length
 }
 else // variable length - just what you retrieved
 {
 *retrieveDataLen = headeredTxAssemblyBufDataLen;  // since you know you have at least ONE header, include the header in the returned length
 }
// reset txassemblybuf offset pointer
m_copyToOutputIndex = 0; 
gotSomething = true;
m_usTimeToTransmitStartedTfdf = FOREVER_IN_THE_FUTURE; // turn off timer
 *whatIGotWasQueueData = false;
 m_mapfhplvo = 0xffff; // FHP is first octet of idle fill packet TODO should this be lvo ever?
 }
// else nothing in buffer - gotSomething stays false
else
{
klmprintf("getPacketToTx nothinginbuffer\n");fflush(stdout);
}
}
m_qSeqCtrlTfdfs_mutex.unlock();
#endif // NONEEDFORGETPACKETTOTX
return gotSomething;
}
*/
class kmasterChannel
{
    public:
        char m_parentstr[100];
        int m_MC_ID; // aggregate of (tfvn * 65536) + scid
        int m_MC_Transfer_Frame_Type;
        int m_MC_SpacecraftId;
        bool m_mc_VCIDs[MAX_VCIDS];
        int m_MC_VC_Multiplexing_Scheme;
        bool m_mcFrameService; // is this an mc frame service mcid?
        bool m_ocfLossFlag; // flag to say you may have lost an ocf (only detectable by frame count error), reset with each delivery (indication)
        bool m_McFrameServiceLossFlag; // flag to say you lost a packet - set when frmae counter error detected, reset on delivery (indication)
        kphysicalChannel *m_parentphyschan;
        std::map <int,kvcid *> m_vcidmap;

        // for ocf delivery countdown
        unsigned char m_ocfBuf[MAX_OCF_LENGTH];
        int m_ocfLen; // local copy of ocf length (length of zero says there's no ocf)
        int m_vcidThatDeliveredMostRecentOcf; // the vcid of the frame that delivered the most recent ocf
        PMutex m_ocfbuf_mutex;
        unsigned int m_timesToReleaseOcfAfterDelivery; // number of times a new ocf gets included in optional var len frame after being delivered. (managed parameter)
        int m_timesLeftToReleaseOcfAfterDelivery; // how many releases are left for this OCF
        // circular queue for master channel frame service
        CircularPacketQueue * m_qMasterChannelFrameService;
        PMutex m_qMasterChannelFrameService_mutex;

        kmasterChannel ( int my_MC_id ,kphysicalChannel *kpcparent)
        {
            m_timesToReleaseOcfAfterDelivery = -1; // (-1=infinite)number of times a new ocf gets included in optional var len frame after being delivered.
            m_timesLeftToReleaseOcfAfterDelivery = 0; // how many releases are left for this OCF

            m_MC_ID = my_MC_id;
            m_parentphyschan = kpcparent;
            for ( int i = 0 ; i < MAX_VCIDS; i++ )
            {
                m_mc_VCIDs[i] = false;
            }
            m_qMasterChannelFrameService = new CircularPacketQueue ( MAX_FRAME_SIZE * MASTER_CHANNEL_FRAME_SERVICES_IN_QUEUE ); // make ocf circular queue
            m_mcFrameService = false;
            m_ocfLossFlag = false;
            m_McFrameServiceLossFlag = false;
        }
        void setMcFrameService ( bool val ) // say this is a mc frame service mcid
        {
            m_mcFrameService = val; // will pretty much always be set to true
        }
        int getMasterChannelFrameServiceQueueSize ( void )
        {
            return m_qMasterChannelFrameService->get_packet_count();
        }
        //
        // MUST be for an EXISTING master channel (in mib) but for NON-existant VCID/MAPid
        //
        /*
           bool putqMasterChannelFrameService ( unsigned char * masterChannelFrameServiceData, int masterChannelFrameServiceLen )
           {
           m_qMasterChannelFrameService_mutex.lock();
           bool goodappend = m_qMasterChannelFrameService->append ( masterChannelFrameServiceData,masterChannelFrameServiceLen );
           m_qMasterChannelFrameService_mutex.unlock();
           return goodappend;
           }
           bool getqMasterChannelFrameService ( unsigned char * masterChannelFrameServiceData, int * masterChannelFrameServiceLen )
           {
           bool goodretrieve = false;
           m_qMasterChannelFrameService_mutex.lock();
           int qMasterChannelFrameServiceSize = m_qMasterChannelFrameService->retrieve ( masterChannelFrameServiceData,*masterChannelFrameServiceLen ); // give it a length you want
           m_qMasterChannelFrameService_mutex.unlock();
           if ( qMasterChannelFrameServiceSize == 0 )
           {
        // klmprintf ( "retrieved zero len MasterChannelFrameService\n" ); fflush ( stdout );
        goodretrieve = false;
        }
        else
        {
        goodretrieve = true;
         *masterChannelFrameServiceLen = qMasterChannelFrameServiceSize; // return how many bytes you DID get in ptrToLength
         kprMutex.lock();printf ( "got masterChannelFrameService: " ); seedata ( masterChannelFrameServiceData,*masterChannelFrameServiceLen ); printf ( "\n" ); fflush ( stdout );kprMutex.unlock();
         }
         return goodretrieve;
         }
         */
        void masterChannelFrameServiceIndication ( unsigned char *frame, gmasterChannelId GMCID, bool masterChannelFrameLossFlag = false )
        {
            charint lkci;
            lkci.i = 0;
            lkci.c[0] = frame[5]; // lsb
            lkci.c[1] = frame[4]; // msb
            int lmasterChannelFrameServiceLen = lkci.i + 1; // since frame length in the frame is minus-1
            kprMutex.lock();printf ( "masterchan_frame_service_indication %s-%d framelossFlag=%s <",GMCID.PHYSCHAN.c_str(), (GMCID.TFVN * 65536) + GMCID.SCID, masterChannelFrameLossFlag?"true":"false"); seedata ( frame, lmasterChannelFrameServiceLen ); printf ( ">\n" ); fflush ( stdout );kprMutex.unlock();
            m_McFrameServiceLossFlag = false; // reset after delivery
        }
        void deliverMcFrameServiceFrame ( String & physchan, unsigned char * frame,int framelen )
        {
            kprMutex.lock();printf ( "dTu MCid Frame Service frame to %s mcid %d : ",physchan.c_str(), m_MC_ID ); seedata ( frame, framelen ); printf ( "\n" ); fflush ( stdout );kprMutex.unlock();
            gmasterChannelId lGMCID;
            lGMCID.set ( physchan, m_MC_ID >> 16, m_MC_ID & 0xffff);
            masterChannelFrameServiceIndication ( frame, lGMCID , m_McFrameServiceLossFlag ) ;
        }
        bool deliverOcfToMcOcfService ( unsigned char *ocfData, int vcid, bool ocfFrameCountError); // deliver OCF from received frame to the VCID object that holds it
        char *mcktree(void);
        bool getMCidOcfBuf(unsigned char *ptrToOcf,int *ptrToLength,int m_vcid_Transfer_Frame_Type); // pass in fixed or variable
        bool putMCidOcfBuf ( unsigned char *ocfData , int vcid); // ocf stored in MCID buf for transmit operations
        void masterChannelOcfIndication(unsigned char *ocfData, gvcid GVCID, bool ocfLossFlag=false);
};
bool kmasterChannel::putMCidOcfBuf ( unsigned char * ocfData , int vcid) // ocf stored in MCID buf for transmit operations
{
    bool retval = false;
    m_ocfbuf_mutex.lock();
    memcpy(m_ocfBuf, ocfData, MAX_OCF_LENGTH);
    m_ocfLen = MAX_OCF_LENGTH; // only time this gets reset to zero is on construction and on expired delivery count
    m_timesLeftToReleaseOcfAfterDelivery = m_timesToReleaseOcfAfterDelivery; // reset number of new OCF deliveries
    m_vcidThatDeliveredMostRecentOcf = vcid; // the vcid of the frame that delivered the most recently did an ocf transmit request
    m_ocfbuf_mutex.unlock();
    retval = true;
    kprMutex.lock();printf("putMCidOcfBuf to mc %d from vc %d <",m_MC_ID, vcid);seedata(ocfData,4);printf(">\n");fflush(stdout);kprMutex.unlock();
    return retval;
}
bool kmasterChannel::getMCidOcfBuf(unsigned char *ptrToOcf,int *ptrToLength,int vcid_Transfer_Frame_Type) // pass in fixed or variable
{
    bool retval = false;
    m_ocfbuf_mutex.lock(); // only grab the data if this is allowed
    if ( vcid_Transfer_Frame_Type == eFixed ) // if it's a fixed length frame or we're receiving, always return it
    {
        klmprintf("fixed getocf m_timesLeftToReleaseOcfAfterDelivery = %d\n",m_timesLeftToReleaseOcfAfterDelivery);fflush(stdout);
        memcpy(ptrToOcf, m_ocfBuf, MAX_OCF_LENGTH); // grab the data
        *ptrToLength = MAX_OCF_LENGTH; // return how many bytes you DID get in ptrToLength
    }
    else // if variable 
    {
        klmprintf("VARIABLE getocf m_timesLeftToReleaseOcfAfterDelivery = %d\n",m_timesLeftToReleaseOcfAfterDelivery);fflush(stdout);
        if ( m_timesLeftToReleaseOcfAfterDelivery > 0 || m_timesLeftToReleaseOcfAfterDelivery == -1 ) // this count is decremented with each getMCidOcfBuf, ostensibly since the ONLY time it's GOTTEN is right before a transmit
        {
            memcpy( ptrToOcf, m_ocfBuf, MAX_OCF_LENGTH ); // grab the data
            *ptrToLength = MAX_OCF_LENGTH; // return how many bytes you DID get in ptrToLength
            if ( m_timesLeftToReleaseOcfAfterDelivery > 0 )
            {
                m_timesLeftToReleaseOcfAfterDelivery--; // decrement this time if not '-1' (include forever)
            }
        }
        else // if variable and ocf has been retrieved the specified number of times, return a blank ocf indication: a length of 0
        {
            *ptrToLength = 0;
            m_ocfLen = 0; // only time this gets reset to zero is on construction and on expired delivery count
        }
    }
    m_ocfbuf_mutex.unlock();
    return retval;
}
//
// moved to kmasterChannel
//
//
// FOR TRANSMITTER:
// for variable frames, ocf is ONLY returned once (the first time after it's been 'put'), and thereafter it's returned with a length of 0
// for fixed len frames it's returned every single time
// FOR RECEIVER:
//  return it every time you're asked for it
//
bool kvcid::getVcidOcfBuf ( unsigned char * ptrToOcf, int * ptrToLength )
{
    bool allowed = false;
    // get ocf buf from master channel IF you're a vcid that's supposed to carry it
    if ( m_vc_include_OCF == eFalse )  // flag calculated by frame type and allow/require/variable/fixed
    {
        *ptrToLength = 0; // return how many bytes you DID get in ptrToLength
    }
    else // ALLOWED. now what kinda ocf do you get? var = certain number of times; fixed - ocf every time
    {
        allowed = true;
        m_myMCID->getMCidOcfBuf(ptrToOcf,ptrToLength,m_vcid_Transfer_Frame_Type); // pass in fixed or variable
    }
    return allowed;
}	
// klm918 decrementedUponGet() void kvcid::decrementMCidOcfDeliveryCount ( void ) // decrement the number of times this ocf needs to be delivered - 4.1.5.4 note 6
// klm918 decrementedUponGet() {
/*
   if ( m_vcid_Transfer_Frame_Type == eVariable ) // if it's a fixed length frame or we're receiving, always return it
   {
   m_ocfbuf_mutex.lock();
// only decrement vcid delivery count if NONZERO ocf len AND there is a number of times left AND it's not the magic "infinity" number (0xffffffff)
if ( m_vcid_ocfLen > 0 && m_timesLeftToReleaseOcfAfterDelivery != -1 && m_timesLeftToReleaseOcfAfterDelivery > 0) // 32 bit max number = forever
{
m_timesLeftToReleaseOcfAfterDelivery--;
if ( m_timesLeftToReleaseOcfAfterDelivery == 0 ) // just delivered its last time
{
m_vcid_ocfLen = 0; // only time this gets reset to zero is on construction and on expired delivery count
}
}
m_ocfbuf_mutex.unlock();
}
*/
// klm918 decrementedUponGet() }
class kphysicalChannel
{
    public:
        char m_parentstr[100];
        // uzw uslptx;
        int m_OIDframeCounter;
        unsigned char m_headeredOIDframeData[MAX_FRAME_SIZE+3]; // constRules/FHP + max-frame-size-of-idle-data
        unsigned char m_pcOIDdata[MAX_FRAME_SIZE+3]; // constRules/FHP + max-frame-size-of-idle-data
        int m_OIDframeDataIndex;
        // klmoptional
        char m_multicast_addr[20]; // klmoptional
        int m_TXport; // port to tx on
        int m_rxport; // port to Rx on
        kUDPtxSocket m_txsock; //klmdebug
        kUDPRXSocket m_RXsock; //klmdebug
        // end of klmoptional
        String m_Name;
        PMutex m_txMutex; // grab mutex to transmit so truncated frames can slip in
        int m_pc_Transfer_Frame_Type;
        int m_pc_Transfer_Frame_Length;
        int m_Transfer_Frame_Version_Number;
        int m_MC_Multiplexing_Scheme;
        int m_Presence_of_Isochronous_Insert_Zone;
        int m_Isochronous_Insert_Zone_Length;
        unsigned char m_IsochronousInsertZoneData[MAX_ISOCHRONOUS_DATA_LENGTH];
        int m_Presence_of_Frame_Error_Control;
        int m_Frame_Error_Control_Length;
        bool m_pchan_Generate_OID_Frame; // post oct 2016 new value post oct 2016 
        unsigned char m_fecfData[MAX_FECF_SIZE +1]; //
        PMutex m_qFecfData_mutex;
        bool m_insertZoneLossFlag; // flag to say the insert zone may have been lost (only detectable by frame count errors). flag set upon frame count error detection, reset to false after insert zone indication delivery

        int m_Maximum_Number_of_Transfer_Frames_Given_to_the_Coding_And_Sync_Sublayer_as_a_Single_Data_Unit;
        int m_PhyschanMaxRepetitionsToCodingAndSyncSublayer;
        std::map <int,kmasterChannel *> m_MCmap;

        // circular queue for insert service
        CircularPacketQueue * m_qIsochInsertService;
        PMutex m_qIsochInsertService_mutex;
        char *PCktree(void);

        kphysicalChannel ( const char * name )
        {
            m_Name.clear();
            m_Name.append ( name );
            memset(m_fecfData,'f',MAX_FECF_SIZE);
            // m_qIsochInsertService = new CircularPacketQueue ( MAX_INSERT_ZONE_SIZE * INSERT_ZONES_IN_QUEUE ); // make ocf circular queue
            m_OIDframeCounter = 0;
            m_insertZoneLossFlag = false;
        }
        void lockPhyschanTxLock()
        {
            m_txMutex.lock();
        }
        void unlockPhyschanTxLock()
        {
            m_txMutex.unlock();
        }
        int getqIsochInsertServiceSize ( void )
        {
            return m_qIsochInsertService->get_packet_count();
        }
        void putInsertZone ( unsigned char * isochInsertZoneServiceData) // put into member variable
        {
            m_qIsochInsertService_mutex.lock();
            memcpy(m_IsochronousInsertZoneData, isochInsertZoneServiceData, m_Isochronous_Insert_Zone_Length); // specified in MIB parameter PHYSICAL_CHANNEL_Isochronous_Insert_Zone_Length
            m_qIsochInsertService_mutex.unlock();
        }
        void getInsertZone ( unsigned char * isochInsertZoneServiceData, int *isochInsertZoneServiceDataLen ) // get from member variable
        {
            m_qIsochInsertService_mutex.lock();
            memcpy(isochInsertZoneServiceData, m_IsochronousInsertZoneData, m_Isochronous_Insert_Zone_Length );
            *isochInsertZoneServiceDataLen = m_Isochronous_Insert_Zone_Length;
            m_qIsochInsertService_mutex.unlock();
        }
        void putFecf ( unsigned char * fecfData ) // put into member variable
        {
            m_qFecfData_mutex.lock();
            memcpy((char *)m_fecfData, fecfData, m_Frame_Error_Control_Length ); // guarantee no more than specified in MIB
            m_qFecfData_mutex.unlock();
        }
        void getFecf ( unsigned char * fecfData, int *fecfDataLen ) // get from member variable
        {
            m_qFecfData_mutex.lock();
            memcpy(fecfData, m_fecfData, m_Frame_Error_Control_Length ); // guarantee no more than specified in MIB
            *fecfDataLen = m_Frame_Error_Control_Length;
            m_qFecfData_mutex.unlock();
        }
        // these two methods are leftover from when iz was queued
        bool putqInsertZoneService ( unsigned char * isochInsertZoneServiceData, int isochInsertZoneServiceDataLen )
        {
            m_qIsochInsertService_mutex.lock();
            bool goodappend = m_qIsochInsertService->append ( isochInsertZoneServiceData,isochInsertZoneServiceDataLen );
            m_qIsochInsertService_mutex.unlock();
            return goodappend;
        }
        bool getqInsertZoneService ( unsigned char * isochInsertZoneServiceData, int * isochInsertZoneServiceDataLen )
        {
            bool goodretrieve = false;
            m_qIsochInsertService_mutex.lock();
            int qIsochInsertServiceSize = m_qIsochInsertService->retrieve ( isochInsertZoneServiceData,*isochInsertZoneServiceDataLen ); // give it a length you want
            m_qIsochInsertService_mutex.unlock();
            if ( qIsochInsertServiceSize == 0 )
            {
                // klmprintf ( "retrieved zero len InsertZoneService\n" ); fflush ( stdout );
                goodretrieve = false;
            }
            else
            {
                goodretrieve = true;
                *isochInsertZoneServiceDataLen = qIsochInsertServiceSize; // return how many bytes you DID get in ptrToLength
                kprMutex.lock();printf ( "got isochInsertZoneServiceData: " ); seedata ( isochInsertZoneServiceData,*isochInsertZoneServiceDataLen ); printf ( "\n" ); fflush ( stdout );kprMutex.unlock();
            }
            return goodretrieve;
        }
        int txFrame ( unsigned char * txthisframe, int nbytes , int repetitions)
        {
            static int killthisDROPPINGFRAME=0;
            int retval = 0;
            // send the assembled uslp transfer frame to its destination the specified number of times
            m_txMutex.lock(); // grab mutex to transmit so truncated frames can slip in
            if ( repetitions < 0 ) repetitions = 1;
            for ( int numberOfTimesDelivered = 0 ; numberOfTimesDelivered < repetitions ; numberOfTimesDelivered++ )
            {
                int nb = -1;
                killthisDROPPINGFRAME++;
                kprMutex.lock();printf ( "klmq txoat %5lld length %d: ",globalUsTimeNow, nbytes ); seeframe ( txthisframe,nbytes ); fflush(stdout);kprMutex.unlock();
                nb = m_txsock.write ( txthisframe, nbytes, m_multicast_addr, m_TXport );

                // check for socket errors
                if ( nb != nbytes )
                {
                    // alarm with transmission error but keep going as if it worked
                    fprintf ( stderr, "main:  socket write error, nb=%d, nbytes=%d -- %s\n", nb, nbytes, m_txsock.get_syserrstr() );
                    fflush ( stderr );
                    retval = -1;
                }
                else
                {
                    if ( retval != -1 ) // so some failure will stick even if the next one succeeds
                    {
                        retval = nb;
                    }
                }
            }
            //klmq sleep(KLMTXDELAY); // DELAY ON EVERY FRAME for overseas udp ordering
            /*
               struct timespec ts;
               ts.tv_sec = 0;
               ts.tv_nsec = 500000000; // half a second
               nanosleep(&ts,NULL);
               */
            m_txMutex.unlock(); // grab mutex to transmit so truncated frames can slip in
            return retval;
        }
        //
        // indication to conform to spec
        //
        void insertZoneIndication(unsigned char * izdata, String physchan, bool insertZoneFrameLossFlag = false);
        void deliverIZ ( unsigned char * izdata, int izlen, bool izLossError )
        {
            kprMutex.lock();printf ( "dTu IZN l%2d %s ",m_Isochronous_Insert_Zone_Length, m_Name.c_str() ); fflush ( stdout ); seedata ( izdata,izlen ); printf(" loss flag %s",izLossError?"true":"false"); printf ( "\n" ); fflush ( stdout );kprMutex.unlock();
            insertZoneIndication(izdata, m_Name, izLossError); // TODO frame loss flag 
        }
        // may include IZ and may include OCF
        // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frames void txOIDframe(unsigned char * ocfData, int ocfDataLen , int MCid, int frameCounterOctets, long long frameCounterValue); // called by physchan pointer but needs vcid-specific OID (since include flags are per-timerexpiring-vcid)
        void txOIDframe( int MCid, int frameCounterOctets, long long frameCounterValue); // called by physchan pointer but needs vcid-specific OID (since include flags are per-timerexpiring-vcid)
        void putOIDframeData ( unsigned char * str )
        {
            // fill rest of OID frame data with 'mission specific' idle frame data
            strcpy((char *)m_pcOIDdata, (char *)str); // leave room for header (protocolID and FHP/LVO)
            int lsourceLen = strlen ((char *)m_pcOIDdata); // plus header
            //
            // fill out idle data to max frame size for later truncation as needed
            //
            for ( int lfrom=0,lto = 0; lto < MAX_FRAME_SIZE; )
            {
                m_pcOIDdata[lto++] = m_pcOIDdata[lfrom++];
                if ( lfrom == lsourceLen )
                {
                    lfrom = 0;
                }
            }
        }
};
// NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frames
// void kphysicalChannel::txOIDframe(unsigned char * ocfData, int ocfDataLen , int MCid, int frameCounterOctets, long long frameCounterValue) // called by physchan pointer but needs vcid-specific OID (since include flags are per-timerexpiring-vcid)
void kphysicalChannel::txOIDframe( int MCid, int frameCounterOctets, long long frameCounterValue) // called by physchan pointer but needs vcid-specific OID (since include flags are per-timerexpiring-vcid)
{
    //
    // influence ocf inclusion with managed parameter
    //
    unsigned char lblank[4] = {0,0,0,0};
    // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frames
    // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID framesif ( m_MCmap[MCid]->m_vcidmap[63]->m_vc_include_OCF == eFalse) // ocf is individually allowed/prohibited per vcid 
    // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frames{
    // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frames    ocfDataLen = 0; // eliminate OCF by setting length to zero if not supposed to have one
    // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frames}
    klmprintf("txOID fco %d frametx\n",frameCounterOctets);fflush(stdout);
    // get tfvn and scid from MCid
    int ltfvn = MCid >> 16;
    int lscid = (int)(MCid & (int)0xFFFF);
    // put protocolID of 31 into frame as per CCSDS 732.1-R-2 4.1.4.2.3.3.j
    // repeated idle data from mibconfig the right length to make the frame m_pc_Transfer_Frame_Length
    int lOidBytesIncludingConstRulesAndLvo = m_pc_Transfer_Frame_Length // frame length
        - FRAME_PRIMARY_HEADER_OCTETS // frame header len (if not truncated)
        // vc count octets is always 0
        - m_Isochronous_Insert_Zone_Length // calculated insert zone length
        //
        // - ocfDataLen commented out after 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frames
        //
        // never any security header in idle frames - m_LengthOfSpaceDataLinkSecurityHeader // MIB security header len
        // never any security in idle frames - m_LengthOfSpaceDataLinkSecurityTrailer // MIB security trailer len
        // never any fecf in idle frame
        - m_Frame_Error_Control_Length  // fecfLen
        - frameCounterOctets // frame counter octets
        //
        ; 
    // figure LVO - it must be the first-spot-is-zero-offset-to-the-last-octet-of-the frame, not give the NUMBER of octets in the frame

    int lOidLvo = lOidBytesIncludingConstRulesAndLvo - 4; // subtract 3 (length of the const Rules and LVO octets ) and subtract 1 to point AT the last octet instead of giving the NUMBER of octets
    // as per 4.1.4.1.9 - TFDF hdr const rule 001
    // as per 4.1.4.2.3.3 note i - protocol id is 31
    m_headeredOIDframeData[0] = 0x3f; // header of OID frame is constRule 001 protocol id 31
    m_headeredOIDframeData[1] = (unsigned char)((lOidLvo>>8) & 0xff); // header of OID frame is constRule 001 upid 31
    m_headeredOIDframeData[2] = (unsigned char)(lOidLvo & 0xff); // header of OID frame is constRule 001 upid 31
    idleFillHere(&m_headeredOIDframeData[3], lOidBytesIncludingConstRulesAndLvo - 3, m_pcOIDdata ); // the idle data IS an encapsulated oid packet
    // fastbit
    int lfirstOctetAfterVcCounters = makeTransferFrameHeaderNoLen( fastbitTxFrame, 
            ltfvn,
            lscid,
            0, // dest_src, 0=scid is SOURCE of frame, 1=scid is DEST of the frame - HARDCODED oid frames are always SOURCE
            63,  // OID vcid // per CCSDS 732.1-R-2 4.1.4.1.7
            0,   // mapid is set to zero as per recent redbook
            0, // endOfTransferFrameHeader
            1, // bypassFlag, // 4.2.8.4 note 1 - "it is not required to maintain a Virtual Channel frame count for OID frames" - so there is no 'sequence' so i use 'expedited'
            0, // here this will always be 0(user data) m_protocolCommandControlFlag - 0 means 'contains user data' 4.1.2.8.2.2.a
            0, // ocfflag will always be 0 - no ocf since from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frames
            frameCounterOctets,// vcSeqCounterOctets
            frameCounterValue // vcSequenceCount // fastbit
            );
    // int buildParamFrameAddLen(unsigned char *fp, int offset,  // output frame and offset of first octet past frame header and vc frame counter to start adding the rest of the frame to
    // 																	bool izflag, int izlen, unsigned char *izdata,  // whether and what iz to add
    // 																	bool schdrflag, int schdrlen, unsigned char *schdrdata,  // whether and what security header to add
    // 																	int tfdflen, unsigned char *tfdfdata,  // what transfer frame data field (including TFDF header) to add
    // 																	bool sctrlrflag, int sctrlrlen, unsigned char *sctrlrdata,  // whether and what security trailer to add
    // 																	bool ocfflag, int ocflen, unsigned char *ocfdata,  // whether and what ocf data to add
    //																	bool fecfflag, int fecflen, unsigned char *fecfdata) // whether and what fecf data to add

    int totalFastbitFrameLen = buildParamFrameAddLen(fastbitTxFrame, 
            lfirstOctetAfterVcCounters, 
            (m_pc_Transfer_Frame_Type == eFixed && m_Presence_of_Isochronous_Insert_Zone == ePresent)?true:false,
            m_Isochronous_Insert_Zone_Length,  // 4.1.4.19
            (unsigned char *)m_IsochronousInsertZoneData, // 4.1.4.1.9 
            false, // sechdrflag no sec hdr on OID frame				// sc hdr flag
            0, // no sec hdr on OID frame 
            (unsigned char *)"", // no sec hdr data on OID frame 
            lOidBytesIncludingConstRulesAndLvo, // tfdf len including header
            m_headeredOIDframeData, // NO NEED to skip first octet because since this isn't coming from the QUEUE it doesn't have the bypass indicator octet in i&t
            false, // sectrlrflag no sec trlr on OID frame				// sc trlr flag
            0, // no sec trlr on OID frame 
            (unsigned char *)"", // no sec trlr data on OID frame 
            m_MCmap[MCid]->m_vcidmap[63]->m_vc_include_OCF, // ocf flag is a managed vc parameter so it is configured in mibconfig for vcid 63
            0,    // ocfLen - can have OCF 4.1.4.1.9 --- NOPE! from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frames
            lblank,   // 4.1.4.1.9 NOPE! from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frames
            (m_Presence_of_Frame_Error_Control == ePresent)?true:false, // fecf flag
            m_Frame_Error_Control_Length,  // fecfLen,
            m_fecfData ); // *fecfData
    kprMutex.lock();printf("hdr: xOID f <");seedata(fastbitTxFrame,totalFastbitFrameLen);printf(">\n");fflush(stdout); kprMutex.unlock();
    // fastbit
    // have the physical channel transmit the frame
    txFrame ( fastbitTxFrame,totalFastbitFrameLen, 1); // one repetition for OID frame
}
bool kmasterChannel::deliverOcfToMcOcfService ( unsigned char *ocfData, int vcid, bool ocfFrameCountError) // deliver OCF from received frame to the VCID object that holds it (from receive operations)
{
    bool retval = false;
    m_ocfbuf_mutex.lock();
    memcpy(m_ocfBuf, ocfData, MAX_OCF_LENGTH);
    m_ocfLen = MAX_OCF_LENGTH; // only time this gets reset to zero is on construction and on expired delivery count
    m_timesLeftToReleaseOcfAfterDelivery = m_timesToReleaseOcfAfterDelivery; // reset number of new OCF deliveries
    m_vcidThatDeliveredMostRecentOcf = vcid; // the vcid of the frame that delivered the most recent ocf
    gvcid lGVCID;
    lGVCID.set( (char *)m_parentphyschan->m_Name.c_str(),m_MC_ID>>16, m_MC_ID & 0xffff, vcid);  // set all parameters of gvcid
    if ( m_vcidmap[vcid] != NULL ) // if this is a valid vcid
    {
        if ( m_vcidmap[vcid]->m_vc_include_OCF ) // if this vcid is participating
        {
            kprMutex.lock();printf("dTu OCF l%2d %s loss flag %s data:",m_ocfLen, m_vcidmap[vcid]->vcktree(),ocfFrameCountError?"true":"false"); seedata(m_ocfBuf,m_ocfLen); printf("\n");fflush(stdout);kprMutex.unlock();
            masterChannelOcfIndication(ocfData, lGVCID,ocfFrameCountError); 
            retval = true;
        }
    }
    m_ocfbuf_mutex.unlock();
    return retval;
}
kvcid::kvcid ( kphysicalChannel *lmyphyschanptr, kmasterChannel *lmymasterchannelid, int lvcid )
{ 
    killthisDroppingFrames = false;
    killthisDummyVcRxFrameCounter = 0; // for COP
    killthisDropNframes = 0; // drop this many every killthisDropEveryNframes frames
    killthisDropEveryNframes = 0;

    m_farmfn = NULL; // init pointer
    m_timedVcidReleasesFlag = false; // assume there are no timed releases (readmibconfig assigns value)
    m_vcidUsTimeToTxMinTimeBetweenVcidFrames = FOREVER_IN_THE_FUTURE;
    m_myPHYSCHAN = lmyphyschanptr;
    m_myMCID = lmymasterchannelid;
    m_GVCID.set((char *)m_myPHYSCHAN->m_Name.c_str(), m_myMCID->m_MC_ID >> 16, m_myMCID->m_MC_ID & 0xffff, lvcid ); // my GVCID to pass to everybody (so far only vc frame service needs this	

    if ( m_myMCID->m_MC_SpacecraftId != global_MY_SPACECRAFT_ID ) // this is a vcid for somebody else
    {
        m_source0Destination1 = 1; // if this bit is 1 then the spacecraft ID in the mcid is the DESTINATION spacecraft id. if 0 it's the source. if parent mcid's spacecraft id isn't MY_SPACECRAFT_ID this will be set to 'destination'
    }
    else
    {
        m_source0Destination1 = 0; // if this bit is 1 then the spacecraft ID in the mcid is the DESTINATION spacecraft id. if 0 it's the source. if parent mcid's spacecraft id isn't MY_SPACECRAFT_ID this will be set to 'destination'
    }
    // 
    // assume no security header (important that vcid63 KNOW there is no security header/trailer)
    //
    m_LengthOfSpaceDataLinkSecurityHeader = 0; // default for all vcids
    m_LengthOfSpaceDataLinkSecurityTrailer = 0;
    m_PresenceOfSpaceDataLinkSecurityHeader = eFalse;
    m_PresenceOfSpaceDataLinkSecurityTrailer = eFalse;
    memset ( m_spaceDataLinkSecurityHeader,0,MAX_FRAME_SIZE );
    memset ( m_spaceDataLinkSecurityTrailer,0,MAX_FRAME_SIZE );
    m_VCID = lvcid;
    for ( int m = 0 ; m < MAX_MAP_IDS; m++ )
    {
        m_vc_MAP_IDs[m] = false;
    }
    m_qVcFrameService = new CircularPacketQueue ( MAX_FRAME_SIZE * VC_FRAME_SERVICES_IN_QUEUE ); // make circular queue
    m_VcidFrameService = false; // default to NOT-a-vcid-frame-service vcid
    resetVcidOidTimer();
    // fill m_vcmaxval[] with the following values: { 0LL, 256LL, 65536LL, 1677216LL, 4294967296LL, 1099611627776LL, 281474976710656LL, 72057594037927936LL };
    m_vcmaxval[0] = 0LL;
    long long lmaxvalmultiple = 256LL;
    for ( int i = 1; i < 8; i++)
    {
        m_vcmaxval[i] = lmaxvalmultiple;
        lmaxvalmultiple *= 256LL;
    }
    // default OID vcid 63 frame counter octet count to 2
    if ( m_VCID == 63) // if this is an OID vcid
    {
        // readmapconfig hardcode-isntantiates a map 0 for vcid 63
        m_vcExpIntCountOctets = 2; // set exp int ount to 2 octets
        m_vcExpIntCountMax = m_vcmaxval[2]; // set max to 2 octets' worth of max
        m_vcExpIntCounter = 0ll; // reset counter
    }
    m_vcidFrameServiceFrameLoss = false; // loss detected by frame count error 
    m_oneMapidOnThisVcid = false; // mapa sdu frame loss flag only true if it's the only mapid on this vcid
    m_vcExpIntCounter = 0ll;      // the current frame count
    m_vcSeqCtrlCounter = 0ll;     // the current frame count
    m_COP_in_Effect = noCopInEffect; // so stray CLCW repetition values aren't assigned to non-cop vcids (like 63)
    m_vc_include_OCF = eFalse; // default to no ocf
    m_vcRequireFixedFrameInclusionOfOcf = eFalse;
    m_allowVariableFrameInclusionOfOcf = eFalse;
    // m_Maximum_delay_in_milliseconds_between_releases_of_frames_of_the_same_VC = 0;
}
kmapid::kmapid ( kphysicalChannel *physchan, int masterchannelid, int vcid, int mapid, kvcid *ptrToVcidParent ) // default constructor
{
    m_deliverFn = NULL;
    m_completePacket = 0; // 0=complete assume packet being delivered is complete - 3.3.2.8 - nonzero says which error happened 
    m_completeMapaSdu = 0; // 0=complete assume sdu being delivered is complete - 3.4.2.6 - nonzero says which error happened 
    m_frameCountError = false; // a frame count error happened 
    m_octetStreamLossFlag = false; // a frame count error happened on an octet stream mapid (only way to detect missing ocf)
    // pkt error counts
    m_PktErrRxNewPacketWithNonEmptyAssemblyBuf = 0; // how many times you've delivered a partial packet to user (only if MP says to)
    m_PktErrRxdContinuationWithNoBeginSegment = 0; // received CONTINUATION packet with NOTHING in the rx assembly buffer (no beginning to tack this onto the end of)
    m_MapaErrRxdStartingMapaWithNonEmptyAssemblyBuf = 0; // received starting mapa with non-empty rxassembly buf
    m_MapaErrRxdContinuingMapaWithEmptyAssemblyBuf = 0; // received continuing packet with NOTHING in the rx assembly buffer (no beginning to tack this onto the end of)
    m_MapaErrRxdVarStartingMapaWithNonEmptyAssemblyBuf = 0; // received starting mapa with NONempty assembly buf IN VARIABLE FRAME
    m_PktErrRxdVarStartingPacketWithNonEmptyAssemblyBuf = 0; // received starting packet with NONempty assembly buf IN VARIABLE FRAME
    m_PktErrRxdVarContinuingPacketWithEmptyAssemblyBuf = 0; // received continuing packet with empty assembly buf IN VARIABLE FRAME
    m_MapaErrRxdVarContinuingMapaWithEmptyAssemblyBuf = 0; // received continuing mapa with empty rxassembly buf IN VARIABLE FRAME
    m_PktErrRxdVarEndingSegPacketWithEmptyAssemblyBuf = 0;
    m_MapaErrRxdVarEndingSegMapaWithEmptyAssemblyBuf = 0;
    m_PktErrRxdPktEndspanWithTooShortRxAssemblyBuf = 0; // rxd endspan but concatenation was shorter than inherent packet length said it would be. musta missed the continuation packet in an earlier frame
    m_MapaErrRxdVarConstRule111WithNonEmptyAssemblyBuf = 0; // rxd MAPA anything in var frame with nonempty rxbuffer (var mapas are one-per-tfdf and are never copied into rxAssemblyBuf so if anything in there it's an error)
    m_SdlsErrRxdWithNonEmptyAssemblyBuf = 0; // ANY time you rx an sdls error, this is the error
    // stuff
    m_rxcount = 0;
    m_protocolCommandControlFlag = 0; // eventually copy this from a received prox-1 frame
    m_map_PHYSCHANptr = physchan;
    m_map_MASTER_CHANNEL_ID = masterchannelid;
    m_map_VCID = vcid;
    m_map_MAPID = mapid;
    m_txThisPvnNext = -1; // -1 says there's NO tx-this-pvn-next
    m_usTimeToTransmitStartedTfdf = FOREVER_IN_THE_FUTURE; // time to empty the tfdf if anything is in it
    m_txBufStartsWithContinuation = false; // flag to say tx assembly buf currently starts with a continuation from previous frame
    m_copyToOutputIndex = 0; // tfdf construction buffer
    //
    // use only one circular queue per map even for packets - different PVNs can come in on the same mapid. 
    // they come in fifo and will be split into consecutive TFDFs so it's ok to put them all into one queue
    //
    m_qSeqCtrlTfdfs = new CircularPacketQueue ( (MAX_FRAME_SIZE - MINIMUM_FRAME_HEADER_SIZE) * TFDFS_IN_QUEUE ); // max possible tfdf size is a tfdf with no iz, no ocf, no fecf, no security header/trailer, and no frame counter octets
    m_qExpeditedTfdfs = new CircularPacketQueue ( (MAX_FRAME_SIZE - MINIMUM_FRAME_HEADER_SIZE) * TFDFS_IN_QUEUE ); // max possible tfdf size is a tfdf with no iz, no ocf, no fecf, no security header/trailer, and no frame counter octets
    // m_qSeqCtrlTfdfs = new CircularPacketQueue ( 50 ); // max possible tfdf size is a tfdf with no iz, no ocf, no fecf, no security header/trailer, and no frame counter octets
    m_RxAssemblyIndex[0] = m_RxAssemblyIndex[1] = 0; // assembly index per pvn (where to add the next octets)
    //
    // end sap stuff
    //
    m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets = 0;  // will be initialized by readmibconfig
    m_myVcidParent = ptrToVcidParent;
    // 
    // rx assembly bufs are allocated at end of readMibConfig. if service type is packet, then one-for-each-valid-pvn is allocated for each map, else only one is allocated for each map
    //
    m_spanningPvn[0] = m_spanningPvn[1] = packetInfoMib.m_minimumValidPvn; // init to a good value
    //
    // packet/mapa constuction variables
    m_copyToOutputIndex = 0;
    m_ccsdsPacket = false;
    m_constRules = NO_VALUE;
    m_mapfhplvo = NO_VALUE; // for empty buffers, fhp = 0, lvo = 0
    m_fixedlen = true;
    m_completeInbuf = false;
    m_beginSpan = false;
    m_middleSpan = false;
    m_endSpan = false;
    m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR = 65514;
    m_GMAPID.set( m_map_PHYSCHANptr->m_Name, (m_map_MASTER_CHANNEL_ID>>16)/*tfvn*/,(m_map_MASTER_CHANNEL_ID & 0xffff)/*scid*/, m_map_VCID, m_map_MAPID);
    m_SduId = 0;
    m_map_octetStreamDeliverLength = 0; // 3.5.3.3.4 note 2 - this must be nonzero by the time the MAP_CHANNEL_Service_Data_Unit_Type parameter hits if it's set to octet_stream
    m_map_octetStreamRequestLength = 0; // 3.5.3.3.4 note 2 - this must be nonzero by the time the MAP_CHANNEL_Service_Data_Unit_Type parameter hits if it's set to octet_stream
    m_mapaSduFrameCountLossFlag = false; // mapa sdu frame loss DUE TO FRAME COUNT ANOMALY ONLY  (and then only if only one mapid on this vcid)
    m_txBypassFlag = eSequenceControlled; // default to sequence controlled
}
void kmapid::deliverDataField ( int constrRules,int protocolId, int fhplvo, unsigned char * data, int dataLen, int protocolCommandControlFlag, int sqc0exp1 ) // permapid has INHERENT m_frameCounter access
{
    int lpvn = packetInfoMib.m_minimumValidPvn; // local keep-up-with-pvn variable
    int ldataIndex = 0; // index through incoming data for packet
    //
    // gotta parse individual packets in delivered data field and assign to rx-assembly-buf per pvn. if multiplexingPvns is true, set pvn to packetInfoMib.m_minimumValidPvn;
    // 
    kprMutex.lock();printf ( "deliver DataField Vcid %d mapid %d Constr %d protId %d sq0exp1 %d fhplvo %d LEN %d rxabidx %d: <", m_map_VCID,m_map_MAPID,constrRules,protocolId, sqc0exp1, fhplvo, dataLen ,m_RxAssemblyIndex[sqc0exp1]); seedata ( data, dataLen ); printf("> rxAssemblyBuf idx %d <",m_RxAssemblyIndex[sqc0exp1]);seedata(m_RxAssemblyBuf[sqc0exp1],m_RxAssemblyIndex[sqc0exp1]);printf(">\n"); fflush ( stdout );kprMutex.unlock();
    bool upidMpMismatch = false;
    switch(protocolId ) // issue error message if protocol id rxd is not what the mapid is configured for
    {
        case 0: if (m_map_ServiceDataUnitType != eMAP_PACKET ) // rxd map packet upid (4.1.4.2.3.3)
                {
                    upidMpMismatch = true;
                }
                break;
        case 1: // cop 1
                break;
        case 2: // cop P
                break;
        case 3: // SDLS commands
                break;
        case 4: if (m_map_ServiceDataUnitType != eOCTET_STREAM ) // rxd map packet upid (4.1.4.2.3.3)
                {
                    upidMpMismatch = true;
                }
                break;
        case 5: if (m_map_ServiceDataUnitType != eMAPA_SDU ) // rxd map packet upid (4.1.4.2.3.3)
                {
                    upidMpMismatch = true;
                }
                break;
        default:
                break;
    }
    if ( upidMpMismatch )
    {
#define MAX_PROTOCOL_ID_TEXT_SIZE 15
        char upidRxd[MAX_PROTOCOL_ID_TEXT_SIZE];
        char Mptype[MAX_PROTOCOL_ID_TEXT_SIZE];
        switch(protocolId)
        {
            case 0: strcpy(upidRxd,"MAP_PACKET");
                    break;
            case 4: strcpy(upidRxd,"OCTET_STREAM");
                    break;
            case 5: strcpy(upidRxd,"MAPA_SDU");
                    break;
            default: strcpy(upidRxd,"undefined");
                     break;
        }
        switch(m_map_ServiceDataUnitType)
        {
            case eMAP_PACKET: strcpy(upidRxd,"MAP_PACKET");
                              break;
            case eOCTET_STREAM: strcpy(upidRxd,"OCTET_STREAM");
                                break;
            case eMAPA_SDU: strcpy(upidRxd,"MAPA_SDU");
                            break;
            default: strcpy(upidRxd,"undefined");
                     break;
        }
        kprMutex.lock();printf ( "ERROR - deliverDataField Vcid %d mapid %d RCVD protId %s seq0exp1 %d different than mapid datatype %s from managed parameters.\n", m_map_VCID,m_map_MAPID,upidRxd,sqc0exp1,Mptype); fflush ( stdout );kprMutex.unlock();
    }
    if ( protocolCommandControlFlag == 1 ) // datafield is a COP command
    {
        deliverToUser ( data, dataLen, 0, eCOP ); 
    }
    else
    {
        switch ( constrRules )
        {
            case CR_000_SPANNING_DATA_UNITS:
                // 
                // detectable error 1: if this is a continuation (fhp != 0) and there's nothing in rxassemblybuf TO continue: deliver up to fhp (if -1, deliver entire thing), then parse good packets
                // detectable error 2: if this packet starts at 0 and there's an UNFINISHED packet in rxassemblybuffer: deliver unfinished packet in rxassemblybuf, then parse this packet as normal
                //
                if ( fhplvo != 0 && m_RxAssemblyIndex[sqc0exp1] == 0 ) // detectable error 1: if this is a continuation (fhp != 0) and there's nothing in rxassemblybuf TO continue: deliver up to fhp (if -1, deliver entire thing), then parse good packets
                {
                    if ( fhplvo == 0xffff ) // empty rxAssemblyBuf and whole rxd packet is continuation
                    {
                        m_completePacket = ePktErrRxdContinuationWithNoBeginSegment; // say there was a packet error
                        deliverPartialSDU( data, dataLen, ePktErrRxdContinuationWithNoBeginSegment,sqc0exp1 ); // deliver this partial packet you just received (if managed parameter says to) and leave m_RxAssemblyIndex[sqcexp] at 0
                        // 
                        // adding mapp_notify_indication and mapp_indication for compliance matrix
                        // 
                        add_packet_indications(data, m_GMAPID, m_txBypassFlag, m_SduId, ePktErrRxdContinuationWithNoBeginSegment,true/*error*/ , SDLSverificationStatusCodeGetter()); // packetQualityIndicatorError = false; 
                        // 
                        // [ ] verified?
                        // 
                    }
                    else // empty rxAssemblyBuf and first part of rxd packet is endspan: endspan with no beginspan - deliver the endspan, then parse the packet from the fhp normally
                    {
                        m_completePacket = ePktErrRxdContinuationWithNoBeginSegment; // say there was a packet error
                        deliverPartialSDU( data, fhplvo, ePktErrRxdContinuationWithNoBeginSegment,sqc0exp1 ); // deliver this partial packet you just received (if managed parameter says to) and leave m_RxAssemblyIndex[sqcexp] at 0
                        // 
                        // adding mapp_notify_indication and mapp_indication for compliance matrix
                        // 
                        add_packet_indications(data, m_GMAPID, m_txBypassFlag, m_SduId, ePktErrRxdContinuationWithNoBeginSegment,true/*error*/, SDLSverificationStatusCodeGetter() ); // packetQualityIndicatorError = false; verificationStatusCode)
                        // 
                        // [ ] verified?
                        // 
                        parsePacketsFromBufLeaveExcessInRxAssemblyBuf(&data[fhplvo],dataLen - fhplvo, sqc0exp1); // parse/deliver packets, pvn obtained from packet, leave excess in m_RxAssemblyBuf, index in m_RxAssemblyIndex[sqcexp], and m_spanningPvn
                    }
                }
                else if ( fhplvo == 0 && m_RxAssemblyIndex[sqc0exp1] != 0 ) // detectable error 2: if this packet starts at 0 and there's an UNFINISHED packet in rxassemblybuffer: deliver unfinished packet in rxassemblybuf, then parse this packet as normal
                {
                    m_completePacket = ePktErrRxdPktStartWithNonEmptyAssemblyBuf; // say there was a packet error
                    // deliver partial packet in m_RxAssemblyBuf (if managed parameter says to) and leave m_RxAssemblyIndex[sqcexp] at 0
                    deliverPartialSDU( m_RxAssemblyBuf[sqc0exp1], m_RxAssemblyIndex[sqc0exp1], ePktErrRxdPktStartWithNonEmptyAssemblyBuf,sqc0exp1 ); 
                    // 
                    // adding mapp_notify_indication and mapp_indication for compliance matrix
                    // 
                    add_packet_indications(m_RxAssemblyBuf[sqc0exp1], m_GMAPID, m_txBypassFlag, m_SduId, ePktErrRxdPktStartWithNonEmptyAssemblyBuf,true/*error*/ , SDLSverificationStatusCodeGetter() ); // int packetQualityIndicatorError 0; verificationStatusCode )
                    // 
                    // [ ] verified?
                    // 
                    // parse/deliver rxd packets, pvn obtained from packet, leave excess in m_RxAssemblyBuf, index in m_RxAssemblyIndex[sqcexp], and m_spanningPvn
                    parsePacketsFromBufLeaveExcessInRxAssemblyBuf(data,dataLen,sqc0exp1); 
                }
                //
                // may yet have a detectable error situation - if we get an end span after missing a continuing packet (rx a construction rule of 000 and non-ffff FHP) - only detectable if lengths are wrong
                //
                else // OK situations: fhp !=0 && rxAssemblyIndex != 0 (rxd continuation pkt with unfinished packet in rxAssemblyBuf) or fhp=0&&rxAssemblyIndex = 0 (rxd start of new packet with empty rxAssemblyBuf).
                {
                    if ( fhplvo == 0xffff ) // this is a CONTINUATION segment that MAY or MAY NOT end
                    {
                        memcpy ( &m_RxAssemblyBuf[sqc0exp1][m_RxAssemblyIndex[sqc0exp1]], data, dataLen ); // copy to end of assembly buffer, assume it's the same PVN as the last one we received for this map
                        m_RxAssemblyIndex[sqc0exp1] += dataLen; // next copy will append after here // TODO assure not > 65536
                        parsePacketsFromBufLeaveExcessInRxAssemblyBuf(m_RxAssemblyBuf[sqc0exp1], m_RxAssemblyIndex[sqc0exp1],sqc0exp1); // see if this addition results in a complete packet
                    }
                    else  // copy up to FHP, deliver, then copy from FHP to end of data
                    {
                        if ( fhplvo == 0 ) // new packet STARTS in first octet (and we've already checked for the nonempty rxassemblybuffer (m_RxAssemblyIndex[sqcexp] != 0) above
                        {
                            // emptied partial packet - continue normally.
                            // ldataIndex pointing to start of first packet 
                            parsePacketsFromBufLeaveExcessInRxAssemblyBuf(data,dataLen, sqc0exp1); // parse/deliver packets, pvn obtained from packet, leave excess in m_RxAssemblyBuf, index in m_RxAssemblyIndex[sqcexp], and m_spanningPvn
                        }
                        else // continuation with new packet starts somewhere other than 0 - this data starts with continuation packet
                        {
                            //
                            // copy continuation segment into last pvn's buffer
                            int loctetsToCopy;
                            bool lisEndingSegment = false; // deliver packet if just concatenated an ENDING segment
                            if (fhplvo == 0xffff ) // continuation segment doesn't finish in this tfdf
                            {
                                loctetsToCopy = dataLen; // copy entire buffer - leave m_spanningPvn unchanged
                            }
                            else // ENDING segment - packet ends at fhplvo and can be delivered
                            {
                                loctetsToCopy = fhplvo; // only copy to next firstheader
                                lisEndingSegment = true; // deliver the packet(s) in m_RxAssemblyBuf
                            }
                            kprMutex.lock();printf("***** cont/end seg len %d at %d ",loctetsToCopy, 0);seedata(data,loctetsToCopy);printf("\n");fflush(stdout);kprMutex.unlock();
                            memcpy(&m_RxAssemblyBuf[sqc0exp1][m_RxAssemblyIndex[sqc0exp1]],data,loctetsToCopy); // copy remainder of data to rx assembly buffer
                            m_RxAssemblyIndex[sqc0exp1] += loctetsToCopy; // move assembly index to end of data just copied
                            if ( lisEndingSegment ) // just concatted an ending segment (up to fhp) - deliver and reset index
                            {
                                kprMutex.lock();printf("***** PARSING spannedpkt len %d ",getPacketLength(m_RxAssemblyBuf[sqc0exp1],m_RxAssemblyIndex[sqc0exp1]));seedata(m_RxAssemblyBuf[sqc0exp1],m_RxAssemblyIndex[sqc0exp1]);printf("\n");fflush(stdout);kprMutex.unlock();
                                //
                                // detectable error situation: endspan may not complete packet (if we lose previous fhp=ffff packet then this endspan won't be full length)
                                //                             ideally you'd deliver both segments independently so you'd have two ostensibly good segments instead of one marked bad where you don't know where the split is.
                                //                             trouble is, the inherent packet length info may not be all there until you concatenate them, so you run the chance of losing that and not knowing until you had a whole 'bad' packet anyway.
                                //                             so i went ahead and just concatenated and declared the whole thing bad.
                                //
                                // since i just copied the new packet all the way to the fhp there may be more than one packet in the assembly buf now
                                // doing it that way does mean i'll hafta have 2xlargestPacket in m_RAB, but it does guarantee i won't overrun my data with a bad packet length and will reset to a GOOD header AT fhp.
                                bool wholePktInBuf = parsePacketsFromBufLeaveExcessInRxAssemblyBuf(m_RxAssemblyBuf[sqc0exp1], m_RxAssemblyIndex[sqc0exp1], sqc0exp1);
                                if ( !wholePktInBuf ) // this was an endspan - if the whole packet was in the buf, parsePacketsFromBufLeaveExcessInRxAssemblyBuf woulda txd it. if only a portion is in there and it's SUPPOSED to be an endspan, you've dropped the continuation packet
                                {
                                    m_completePacket = ePktErrRxdPktEndspanWithTooShortRxAssemblyBuf; // say there was a packet error
                                    // deliver partial packet in m_RxAssemblyBuf (if managed parameter says to) and leave m_RxAssemblyIndex[sqc0exp1] at 0. packet is partial because we got an endspan but concatenation was shorter than indicated packet length so we musta missed a continuation
                                    deliverPartialSDU( m_RxAssemblyBuf[sqc0exp1], m_RxAssemblyIndex[sqc0exp1], ePktErrRxdPktEndspanWithTooShortRxAssemblyBuf,sqc0exp1 ); 
                                    // 
                                    // adding mapp_notify_indication and mapp_indication for compliance matrix
                                    // 
                                    add_packet_indications(m_RxAssemblyBuf[sqc0exp1], m_GMAPID, m_txBypassFlag, m_SduId, ePktErrRxdPktEndspanWithTooShortRxAssemblyBuf,true/*error*/ ,SDLSverificationStatusCodeGetter() ); // packetQualityIndicatorError = false; verificationStatusCode 
                                    // 
                                    // [ ] verified?
                                    // 
                                }
                                // now since you just dealt with PART of the incoming data, reset spanningPvn and index value
                                m_RxAssemblyIndex[sqc0exp1] = 0; // reset this lpvn's assembly index
                                m_spanningPvn[sqc0exp1] = -1; // illegal value to core dump if we use it accidentally
                            }
                            ldataIndex = loctetsToCopy; // set index past what you just copied (if it was an ending segment, ldataIndex will = dataLen and the below while() will immediately exit)
                            // ldataIndex pointing to start of first packet  (or end of frame)
                            parsePacketsFromBufLeaveExcessInRxAssemblyBuf(&data[ldataIndex],dataLen - ldataIndex, sqc0exp1); // parse/deliver packets, pvn obtained from packet, leave excess in m_RxAssemblyBuf, index in m_RxAssemblyIndex[sqc0exp1], and m_spanningPvn
                        }
                    }
                }
                break;
            case CR_001_MAPA_SDU_STARTS_MAY_END:
                //
                // detectable error situation : rxing starting (complete or incomplete) mapa but unfinished segment already in rxAssemblyBuf 
                //
                if ( m_RxAssemblyIndex[sqc0exp1] != 0 ) // rxd starting (complete or incomplete) mapa with NON-EMPTY rxAssemblyBuf - this is an ERROR situation
                {
                    m_completeMapaSdu = eMapaErrRxdStartingMapaWithNonEmptyAssemblyBuf;
                    deliverPartialSDU ( m_RxAssemblyBuf[sqc0exp1], m_RxAssemblyIndex[sqc0exp1], eMapaErrRxdStartingMapaWithNonEmptyAssemblyBuf,sqc0exp1); // if supposed to, deliver partial mapa existing in rxAssemblyBuf, reset m_RxAssemblyIndex to 0 to empty buffer
                    // 
                    // adding mapasdu_notify_indication and mapasdu_indication for compliance matrix
                    // 
                    add_mapasdu_indications(m_RxAssemblyBuf[sqc0exp1], m_GMAPID, m_txBypassFlag, m_SduId, eMapaErrRxdStartingMapaWithNonEmptyAssemblyBuf, true /* lost something*/,SDLSverificationStatusCodeGetter()); 
                    // 
                    // [ ] verified?
                    // 
                }
                // only error situation pertains to data already in rxAssemblyBuffer. once it's dealt with, continue to deal with the rxd mapa, which assumes empty rxAssemblyBuf
                if ( fhplvo == 0xffff ) // rxd starting incomplete mapa with emptyRxAssemblyBuf - ok situation
                {
                    klmprintf("ddf 001 ff %d\n",m_RxAssemblyIndex[sqc0exp1]);fflush(stdout);
                    // TODO alarm if there's something already in here.
                    memcpy ( m_RxAssemblyBuf[sqc0exp1],data,dataLen ); // copy to start of assembly buffer
                    m_RxAssemblyIndex[sqc0exp1] = dataLen; // next copy will append
                }
                else // rxd starting complete mapa with EMPTY rxAssemblyBuf - ok situation - complete data unit in this frame, so deliver data pointer - no need to copy to rxassemblybuf
                {
                    klmprintf("ddf 001 %d %d\n",fhplvo, m_RxAssemblyIndex[sqc0exp1]);fflush(stdout);
                    // no parseable data - deliver straight to user
                    deliverToUser ( data, fhplvo + 1 , lpvn, eMAPA_SDU); // actual length of data is fhplvo + 1
                    // 
                    // adding mapasdu_notify_indication and mapasdu_indication for compliance matrix
                    // 
                    add_mapasdu_indications(data, m_GMAPID, m_txBypassFlag, m_SduId, 0, false , SDLSverificationStatusCodeGetter() ); 
                    // 
                    // [ ] verified?
                    // 
                    m_RxAssemblyIndex[sqc0exp1] = 0;  // done
                }
                break;
            case CR_010_CONTINUING_MAPA_SDU_MAY_END:
                //
                // detectable error situation : rxing continuing/ending mapa but NO beginning segment already in rxAssemblyBuf 
                //
                if ( m_RxAssemblyIndex[sqc0exp1] == 0 ) // rxd starting (complete or incomplete) mapa with NON-EMPTY rxAssemblyBuf - this is an ERROR situation
                {
                    m_completeMapaSdu = eMapaErrRxdContinuingMapaWithEmptyAssemblyBuf;
                    deliverPartialSDU ( data, dataLen, eMapaErrRxdContinuingMapaWithEmptyAssemblyBuf,sqc0exp1); // if supposed to, deliver partial mapa received, reset m_RxAssemblyIndex[sqc0exp1] to 0 to empty buffer
                    // 
                    // adding mapasdu_notify_indication and mapasdu_indication for compliance matrix
                    // 
                    add_mapasdu_indications(m_RxAssemblyBuf[sqc0exp1], m_GMAPID, m_txBypassFlag, m_SduId, eMapaErrRxdContinuingMapaWithEmptyAssemblyBuf, true /* lost something*/,SDLSverificationStatusCodeGetter()); 
                    // 
                    // [ ] verified?
                    // 
                }
                //
                // partial rxd sdu delivered: DONE because nothing to add to rxAssemblyBuf and nothing IN rxAssemblyBuf
                // 
                else // rxd continuation with nonempty rxassembly buf - ok situation
                {
                    if ( fhplvo == 0xffff ) // continuing data unit CONTINUES
                    {
                        klmprintf("ddf 010 ff %d\n",m_RxAssemblyIndex[sqc0exp1]);fflush(stdout);
                        memcpy ( &m_RxAssemblyBuf[sqc0exp1][m_RxAssemblyIndex[sqc0exp1]],data,dataLen ); // copy to end of assembly buffer
                        m_RxAssemblyIndex[sqc0exp1] += dataLen; // next copy will append after here // TODO assure not > 65536
                    }
                    else // continuing data unit ENDS
                    {
                        klmprintf("ddf 010 %d %d\n",fhplvo, m_RxAssemblyIndex[sqc0exp1]);fflush(stdout);
                        memcpy ( &m_RxAssemblyBuf[sqc0exp1][m_RxAssemblyIndex[sqc0exp1]],data,fhplvo + 1 ); // copy a length of fhplvo + 1 (fhplvo is LVO in this context and POINTS TO last octet; length includes +1)
                        m_RxAssemblyIndex[sqc0exp1] += fhplvo + 1; // include the octets copied here // TODO assure not > 65536
                        // no parseable data - deliver straight to user
                        deliverToUser ( m_RxAssemblyBuf[sqc0exp1],m_RxAssemblyIndex[sqc0exp1] , lpvn, eMAPA_SDU); // actual length of data is fhplvo + 1
                        // 
                        // adding mapasdu_notify_indication and mapasdu_indication for compliance matrix
                        // 
                        add_mapasdu_indications(m_RxAssemblyBuf[sqc0exp1], m_GMAPID, m_txBypassFlag, m_SduId, 0, false , SDLSverificationStatusCodeGetter() ); 
                        // 
                        // [ ] verified?
                        // 
                        m_RxAssemblyIndex[sqc0exp1] = 0;  // reset
                    }
                }
                break;
            case CR_011_OCTET_STREAM:
                // octet stream - deliver all data straight to user
                // no way other than frame counter to know if you missed a frame.
                deliverToUser ( data,dataLen , lpvn, eOCTET_STREAM);
                // 
                // adding map_octetStream_indication for compliance matrix
                // 

                map_octetStream_indication(data, m_GMAPID, /* 2/21/2018 4:25 gregKass email removes qos flag m_txBypassFlag,*/ m_octetStreamLossFlag ,SDLSverificationStatusCodeGetter() );
                // 
                // [ ] verified?
                // 
                break;
            case CR_100_UNFINISHED_SEGMENT_STARTS:
                //
                // detectable error: if this segment starts and there's something already in rxAssemblyBuf
                //
                if ( m_RxAssemblyIndex[sqc0exp1] != 0 ) // rxd starting (complete or incomplete) mapa with NON-EMPTY rxAssemblyBuf - this is an ERROR situation
                {
                    int errorEnum = ePktErrRxdVarStartingPacketWithNonEmptyAssemblyBuf; // assume packet diagnostic
                    if ( m_map_ServiceDataUnitType == eMAPA_SDU ) // if this is MAPA change diagnostic
                    {
                        errorEnum = eMapaErrRxdVarStartingMapaWithNonEmptyAssemblyBuf;
                        m_completeMapaSdu = eMapaErrRxdVarStartingMapaWithNonEmptyAssemblyBuf;
                    }
                    else
                    {
                        m_completePacket = ePktErrRxdVarStartingPacketWithNonEmptyAssemblyBuf; // say there was a packet error
                    }
                    deliverPartialSDU ( m_RxAssemblyBuf[sqc0exp1], m_RxAssemblyIndex[sqc0exp1], errorEnum,sqc0exp1); // if supposed to, deliver partial PACKET OR MAPA in the rxAssemblyBuf , reset m_RxAssemblyIndex[sqc0exp1] to 0 to empty buffer
                    if ( m_map_ServiceDataUnitType == eMAPA_SDU ) // if this is MAPA change diagnostic
                    {
                        // 
                        // adding mapasdu_notify_indication and mapasdu_indication for compliance matrix
                        // 
                        add_mapasdu_indications(m_RxAssemblyBuf[sqc0exp1], m_GMAPID, m_txBypassFlag, m_SduId, errorEnum, true /* lost something*/ , SDLSverificationStatusCodeGetter()); 
                        // 
                        // [ ] verified?
                        // 
                    }
                    else // if this is PACKET change diagnostic
                    {
                        // 
                        // adding mapp_notify_indication and mapp_indication for compliance matrix
                        // 
                        add_packet_indications(m_RxAssemblyBuf[sqc0exp1], m_GMAPID, m_txBypassFlag, m_SduId, errorEnum, true/*error*/, SDLSverificationStatusCodeGetter()); // packetQualityIndicatorError = false; verificationStatusCode )
                        // 
                        // [ ] verified?
                        // 
                    }
                }
                //
                // partial rxassemblyBuf sdu delivered - back to normal operations
                // 
                if ( m_map_ServiceDataUnitType == eMAP_PACKET ) // packet data
                {
                    parsePacketsFromBufLeaveExcessInRxAssemblyBuf(data, dataLen, sqc0exp1); // parse out complete packets; leave excess in m_RxAssemblyBuf
                }
                else // just copy to assembly buf
                {
                    memcpy ( m_RxAssemblyBuf[sqc0exp1],data,dataLen ); // copy to start of assembly buffer
                    m_RxAssemblyIndex[sqc0exp1] = dataLen; // next copy will append
                }
                break;
            case CR_101_UNFINISHED_SEGMENT_CONTINUES:
                //
                // detectable error: rxd continuing segment with nothing in rxassemblybuf
                //
                if ( m_RxAssemblyIndex[sqc0exp1] == 0 ) // rxd continuing (complete or incomplete) segment with EMPTY rxAssemblyBuf - this is an ERROR situation
                {
                    int errorEnum = ePktErrRxdVarContinuingPacketWithEmptyAssemblyBuf; // assume packet diagnostic
                    if ( m_map_ServiceDataUnitType == eMAPA_SDU ) // if this is MAPA change diagnostic
                    {
                        errorEnum = eMapaErrRxdVarContinuingMapaWithEmptyAssemblyBuf;
                        m_completeMapaSdu = eMapaErrRxdVarContinuingMapaWithEmptyAssemblyBuf;
                    }
                    else
                    {
                        m_completePacket = ePktErrRxdVarContinuingPacketWithEmptyAssemblyBuf; // say there was a packet error
                    }
                    deliverPartialSDU ( data, dataLen, errorEnum,sqc0exp1); // if supposed to, deliver partial PACKET OR MAPA in the rxAssemblyBuf , reset m_RxAssemblyIndex[sqc0exp1] to 0 to empty buffer
                    if ( m_map_ServiceDataUnitType == eMAPA_SDU ) // if this is MAPA change diagnostic
                    {
                        // 
                        // adding mapasdu_notify_indication and mapasdu_indication for compliance matrix
                        // 
                        add_mapasdu_indications(data, m_GMAPID, m_txBypassFlag, m_SduId, errorEnum, true /* lost something*/, SDLSverificationStatusCodeGetter()); 
                        // 
                        // [ ] verified?
                        // 
                    }
                    else // if this is PACKET change diagnostic
                    {
                        // 
                        // adding mapp_notify_indication and mapp_indication for compliance matrix
                        // 
                        add_packet_indications(data, m_GMAPID, m_txBypassFlag, m_SduId, errorEnum,true/*error*/, SDLSverificationStatusCodeGetter()); // packetQualityIndicatorError = false; verificationStatusCode )
                        // 
                        // [ ] verified?
                        // 
                    }
                }
                //
                // partial rxd sdu delivered: DONE because nothing to add to rxAssemblyBuf and nothing IN rxAssemblyBuf
                // 
                else // rxd continuing segment with non-empty rxAssemblyBuf - ok situation
                {
                    // CONTINUING segment - copy this to rx assembly buf THEN parse if packets
                    memcpy ( &m_RxAssemblyBuf[sqc0exp1][m_RxAssemblyIndex[sqc0exp1]],data,dataLen ); // copy to end of assembly buffer
                    m_RxAssemblyIndex[sqc0exp1] += dataLen; // next copy will append after here // TODO assure not > 65536
                    if ( m_map_ServiceDataUnitType == eMAP_PACKET ) // packet data
                    {
                        parsePacketsFromBufLeaveExcessInRxAssemblyBuf(m_RxAssemblyBuf[sqc0exp1], m_RxAssemblyIndex[sqc0exp1], sqc0exp1); // parse out complete packets; leave excess in m_RxAssemblyBuf
                    }
                }
                break;
            case CR_110_CONTINUED_SEGMENT_ENDS:
                //
                // detectable error: rxd continuing segment with nothing in rxassemblybuf
                //
                if ( m_RxAssemblyIndex[sqc0exp1] == 0 ) // rxd continuing (complete or incomplete) segment with EMPTY rxAssemblyBuf - this is an ERROR situation
                {
                    int errorEnum = ePktErrRxdVarEndingSegPacketWithEmptyAssemblyBuf; // assume packet diagnostic
                    if ( m_map_ServiceDataUnitType == eMAPA_SDU ) // if this is MAPA change diagnostic
                    {
                        errorEnum = eMapaErrRxdVarEndingSegMapaWithEmptyAssemblyBuf;
                        m_completeMapaSdu = eMapaErrRxdVarEndingSegMapaWithEmptyAssemblyBuf;
                    }
                    else
                    {
                        m_completePacket = ePktErrRxdVarEndingSegPacketWithEmptyAssemblyBuf; // say there was a packet error
                    }
                    deliverPartialSDU ( data, dataLen, errorEnum,sqc0exp1); // if supposed to, deliver partial PACKET OR MAPA in the rxAssemblyBuf , reset m_RxAssemblyIndex[sqc0exp1] to 0 to empty buffer
                    if ( m_map_ServiceDataUnitType == eMAPA_SDU ) // if this is MAPA change diagnostic
                    {
                        // 
                        // adding mapasdu_notify_indication and mapasdu_indication for compliance matrix
                        // 
                        add_mapasdu_indications(data, m_GMAPID, m_txBypassFlag, m_SduId, errorEnum, true /* lost something*/, SDLSverificationStatusCodeGetter()); 
                        // 
                        // [ ] verified?
                        // 
                    }
                    else // if this is PACKET change diagnostic
                    {
                        // 
                        // adding mapp_notify_indication and mapp_indication for compliance matrix
                        // 
                        add_packet_indications(data, m_GMAPID, m_txBypassFlag, m_SduId, errorEnum,true/*error*/, SDLSverificationStatusCodeGetter()); // packetQualityIndicatorError = false; verificationStatusCode)
                        // 
                        // [ ] verified?
                        // 
                    }
                }
                //
                // partial rxd sdu delivered: DONE because nothing to add to rxAssemblyBuf and nothing IN rxAssemblyBuf
                // 
                else
                {
                    // CONTINUING segment - copy this to rx assembly buf THEN parse if packets
                    memcpy ( &m_RxAssemblyBuf[sqc0exp1][m_RxAssemblyIndex[sqc0exp1]],data,dataLen /*TODO bytes to copy should only be to end of segment*/ );
                    m_RxAssemblyIndex[sqc0exp1] += dataLen; // include the octets copied here // TODO assure not > 65536
                    if ( m_map_ServiceDataUnitType == eMAP_PACKET ) // assembly buf has parseable packets
                    {
                        parsePacketsFromBufLeaveExcessInRxAssemblyBuf(m_RxAssemblyBuf[sqc0exp1], m_RxAssemblyIndex[sqc0exp1], sqc0exp1); // that should result in NO excess
                    }
                    else // mapasdu is ONE entire data unit
                    {
                        deliverToUser(m_RxAssemblyBuf[sqc0exp1], m_RxAssemblyIndex[sqc0exp1],lpvn,eMAPA_SDU); // lpvn means nothing in this context but must be passed anyway
                        if ( m_map_ServiceDataUnitType == eMAPA_SDU ) // if this is MAPA change diagnostic
                        {
                            // 
                            // adding mapasdu_notify_indication and mapasdu_indication for compliance matrix
                            // 
                            add_mapasdu_indications(m_RxAssemblyBuf[sqc0exp1], m_GMAPID, m_txBypassFlag, m_SduId, 0, false , SDLSverificationStatusCodeGetter() ); 
                            // 
                            // [ ] verified?
                            // 
                        }
                        else // if this is PACKET change diagnostic
                        {
                            // 
                            // adding mapp_notify_indication and mapp_indication for compliance matrix
                            // 
                            add_packet_indications(m_RxAssemblyBuf[sqc0exp1], m_GMAPID, m_txBypassFlag, m_SduId, 0,false/*ok*/, SDLSverificationStatusCodeGetter() ); // packetQualityIndicatorError = true; verificationStatusCode )
                            // 
                            // [ ] verified?
                            // 
                        }
                    }
                    m_RxAssemblyIndex[sqc0exp1] = 0;  // reset and lose any excess, which shouldn't exist in the first place
                }
                break;
            case CR_111_SEGMENT_STARTS_AND_ENDS:
                //
                // pretty much no way to detect a receipt error here
                //
                // deliver to user directly from data buffer (no copying into m_RxAssemblyBuf)
                if ( m_map_ServiceDataUnitType == eMAP_PACKET ) // assembly buf has parseable packets
                {
                    parsePacketsFromBufLeaveExcessInRxAssemblyBuf( data, dataLen , sqc0exp1); // that should result in NO excess
                }
                else // mapasdu is ONE entire data unit
                {
                    //
                    // in variable frame for mapa, rxassemblybuf should ALWAYS be empty. if it's not, deliver what's in there and flag it.
                    //
                    if ( m_RxAssemblyIndex[sqc0exp1] != 0 )
                    {
                        m_completeMapaSdu = eMapaErrRxdVarConstRule111WithNonEmptyAssemblyBuf;
                        deliverPartialSDU ( m_RxAssemblyBuf[sqc0exp1], m_RxAssemblyIndex[sqc0exp1], eMapaErrRxdVarConstRule111WithNonEmptyAssemblyBuf,sqc0exp1); // MAPAs are NEVER copied into rxassemblybuf (delivered straight from databuf) so rxAssemblyBuf should ALWAYS be empty
                        // 
                        // adding mapasdu_notify_indication and mapasdu_indication for compliance matrix
                        // 
                        add_mapasdu_indications(m_RxAssemblyBuf[sqc0exp1], m_GMAPID, m_txBypassFlag, m_SduId, eMapaErrRxdVarConstRule111WithNonEmptyAssemblyBuf, true /* lost something*/, SDLSverificationStatusCodeGetter()); 
                        // 
                        // [ ] verified?
                        // 
                    }
                    deliverToUser( data, dataLen, lpvn,eMAPA_SDU ); // lpvn means nothing in this context but must be passed anyway.
                    // 
                    // adding mapasdu_notify_indication and mapasdu_indication for compliance matrix
                    // 
                    add_mapasdu_indications(data, m_GMAPID, m_txBypassFlag, m_SduId, 0, false, SDLSverificationStatusCodeGetter() ); 
                    // 
                    // [ ] verified?
                    // 
                }
                m_RxAssemblyIndex[sqc0exp1] = 0;  // reset anyway
                break;
            default:
                klmprintf ( "bad const rules\n" );
                fflush ( stdout ); // TODO handle this error
        }
    }
    kprMutex.lock();printf("leaving with m_RxAssemblyIndex[%d] = %d mrxbuf <",sqc0exp1,m_RxAssemblyIndex[sqc0exp1]);seedata(m_RxAssemblyBuf[sqc0exp1],m_RxAssemblyIndex[sqc0exp1]);printf(">\n");fflush(stdout); printf("leaving ddf\n");fflush(stdout);kprMutex.unlock();
}
void kmapid::deliverToUser ( unsigned char * dataToUser, int dataLen, int pvn , int type) // deliver one unit of data to user
{
    char lc = 0x00;
    char ldata01[65536];
    int ldatalen = 65482; // 65482 allowing for 3-octet tfdf header (fhp/lvo for fixed len) // 65484 allowing for 1-octet tfdf header (NO fhp/lvo for variable len)
    for (int i = 0 ; i < ldatalen ; i++ )
    {
        ldata01[i] = lc++;
    }
    ldata01[4] = 0xff;
    ldata01[5] = 0xc3; // length in 4,5 for packet 65482-1, 0xc5 for 65484-1

    const char *ctp = "j";
    switch(type)
    {
        case eMAP_PACKET:
            ctp = "PKT";
            break;
        case eMAPA_SDU:
            ctp = "SDU";
            break;
        case eOCTET_STREAM:
            ctp = "OCT";
            break;
        case eCOP:
            ctp = "COP";
            break;
    }
    kprMutex.lock();printf ("dTu sDu %s l%2d %s-%6d-%02d-%02d-%02d ",ctp,dataLen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID, pvn); seedata(dataToUser, dataLen); printf("\n"); fflush(stdout);kprMutex.unlock();
    if ( ldata01[0] == 'j') {} // dummy compilershutup use

    if ( m_deliverFn != NULL )
    {
        printf("killthis %s calling mdeliverfn at %p\n", mapktree(),m_deliverFn);fflush(stdout);
        m_deliverFn(dataToUser,dataLen,type);
    }



    // killthis dummy verification
    /*
       if (memcmp((const char *)dataToUser,(const char *)ldata01,ldatalen) == 0)
       {
       klmprintf("dTu sDu bigframe check is EQUAL\n");fflush(stdout);
       }
       else
       {
       klmprintf("dTu sDu bigframe check is not equal\n");fflush(stdout);
       }
       if ( ldatalen == dataLen ) 
       {
       klmprintf("dTu sDu bigframe LENGTH check is EQUAL\n");fflush(stdout);
       }
       else
       {
       klmprintf("dTu sDu bigframe LENGTH check is not equal\n");fflush(stdout);
       }
       */
}
void kmapid::deliverPartialSDU(unsigned char *buf, int buflen, int pkterr, int sqc0exp1 ) // deliver partial packet - may not have enough info to determine PVN
{
    // announce error
    switch(pkterr)
    {
        case ePktErrRxdPktStartWithNonEmptyAssemblyBuf:
            // report and count error
            kprMutex.lock();printf ("dTu sDu pkterr rxd 0 offset pkt with NONempty rxassembly buf l%2d %s-%6d-%02d-%02d pvn ?",buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            m_PktErrRxNewPacketWithNonEmptyAssemblyBuf++; // count it
            // if supposed to, deliver partial sdu
            if ( packetInfoMib.m_Require_Incomplete_Packet_Delivery_To_User_At_Receiving_End == eTrue)
            {
                kprMutex.lock();printf ("dTu sDu PARTIAL pkt %d l%2d %s-%6d-%02d-%02d pvn ?", pkterr, buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            }
            // always count it, always reset, but only DELIVER if MP says to deliver
            break;
        case ePktErrRxdContinuationWithNoBeginSegment:
            // report and count error
            kprMutex.lock();printf ("dTu sDu pkterr rxd continuation with no beginning l%2d %s-%6d-%02d-%02d pvn ?",buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            m_PktErrRxdContinuationWithNoBeginSegment++; // count it
            // if supposed to, deliver partial sdu
            if ( packetInfoMib.m_Require_Incomplete_Packet_Delivery_To_User_At_Receiving_End == eTrue)
            {
                kprMutex.lock();printf ("dTu sDu PARTIAL pkt %d l%2d %s-%6d-%02d-%02d pvn ?", pkterr, buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            }
            // always count it, always reset, but only DELIVER if MP says to deliver
            break;
        case eMapaErrRxdStartingMapaWithNonEmptyAssemblyBuf:
            // report and count error
            kprMutex.lock();printf ("dTu sDu MAPAerr rxd Starting MAPA with NONempty rxassembly buf l%2d %s-%6d-%02d-%02d pvn ?",buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            m_MapaErrRxdStartingMapaWithNonEmptyAssemblyBuf++;
            // if supposed to, deliver partial sdu
            if ( global_Require_Incomplete_MAPA_Delivery_To_User_At_Receiving_End == eTrue ) // mapa 
            {
                kprMutex.lock();printf ("dTu sDu PARTIAL MAPA %d l%2d %s-%6d-%02d-%02d pvn ?", pkterr, buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            }
            break;
        case eMapaErrRxdContinuingMapaWithEmptyAssemblyBuf:
            // report and count error
            kprMutex.lock();printf ("dTu sDu MAPAerr rxd continuing MAPA with empty rxassembly buf l%2d %s-%6d-%02d-%02d pvn ?",buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            m_MapaErrRxdContinuingMapaWithEmptyAssemblyBuf++;
            // if supposed to, deliver partial sdu
            if ( global_Require_Incomplete_MAPA_Delivery_To_User_At_Receiving_End == eTrue ) // mapa 
            {
                kprMutex.lock();printf ("dTu sDu PARTIAL MAPA %d l%2d %s-%6d-%02d-%02d pvn ?", pkterr, buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            }
            break;
        case ePktErrRxdPktEndspanWithTooShortRxAssemblyBuf: // received endspan with too short packet in rx assembly buf
            kprMutex.lock();printf ("dTu sDu pkterr rxd endspan too short rxassembly buf l%2d %s-%6d-%02d-%02d pvn ?",buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            m_PktErrRxdPktEndspanWithTooShortRxAssemblyBuf++; // received continuing packet with empty assembly buf
            if ( packetInfoMib.m_Require_Incomplete_Packet_Delivery_To_User_At_Receiving_End == eTrue)
            {
                kprMutex.lock();printf ("dTu sDu PARTIAL pkt tooshort %d l%2d %s-%6d-%02d-%02d pvn ?", pkterr, buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            }
            break;
        case eMapaErrRxdVarStartingMapaWithNonEmptyAssemblyBuf: // received starting MAPA with NONempty assembly buf IN VARIABLE FRAME
            kprMutex.lock();printf ("dTu sDu MAPAerr VAR rxd starting MAPA with NONempty rxassembly buf l%2d %s-%6d-%02d-%02d pvn ?",buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            m_MapaErrRxdVarStartingMapaWithNonEmptyAssemblyBuf++; // received starting MAPA with NONempty assembly buf IN VARIABLE FRAME
            if ( global_Require_Incomplete_MAPA_Delivery_To_User_At_Receiving_End == eTrue ) // mapa 
            {
                kprMutex.lock();printf ("dTu sDu PARTIAL MAPA %d l%2d %s-%6d-%02d-%02d pvn ?", pkterr, buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            }
            break;
        case ePktErrRxdVarStartingPacketWithNonEmptyAssemblyBuf: // received starting packet with NONempty assembly buf IN VARIABLE FRAME
            kprMutex.lock();printf ("dTu sDu pkterr VAR rxd starting pkt with NONempty rxassembly buf l%2d %s-%6d-%02d-%02d pvn ?",buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            m_PktErrRxdVarStartingPacketWithNonEmptyAssemblyBuf++; // received starting packet with NONempty assembly buf IN VARIABLE FRAME
            if ( packetInfoMib.m_Require_Incomplete_Packet_Delivery_To_User_At_Receiving_End == eTrue)
            {
                kprMutex.lock();printf ("dTu sDu PARTIAL pkt %d l%2d %s-%6d-%02d-%02d pvn ?", pkterr, buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            }
            break;
        case eMapaErrRxdVarContinuingMapaWithEmptyAssemblyBuf: // received continuing MAPA with empty assembly buf IN VARIABLE FRAME
            kprMutex.lock();printf ("dTu sDu MAPAerr VAR rxd continuing MAPA with empty rxassembly buf l%2d %s-%6d-%02d-%02d pvn ?",buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            m_MapaErrRxdVarContinuingMapaWithEmptyAssemblyBuf++; // received continuing MAPA with empty assembly buf IN VARIABLE FRAME
            if ( global_Require_Incomplete_MAPA_Delivery_To_User_At_Receiving_End == eTrue ) // mapa 
            {
                kprMutex.lock();printf ("dTu sDu PARTIAL MAPA %d l%2d %s-%6d-%02d-%02d pvn ?", pkterr, buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            }
            break;
        case ePktErrRxdVarContinuingPacketWithEmptyAssemblyBuf: // received continuing packet with empty assembly buf IN VARIABLE FRAME
            kprMutex.lock();printf ("dTu sDu pkterr VAR rxd continuing pkt with empty rxassembly buf l%2d %s-%6d-%02d-%02d pvn ?",buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            m_PktErrRxdVarContinuingPacketWithEmptyAssemblyBuf++; // received continuing packet with empty assembly buf IN VARIABLE FRAME
            if ( packetInfoMib.m_Require_Incomplete_Packet_Delivery_To_User_At_Receiving_End == eTrue)
            {
                kprMutex.lock();printf ("dTu sDu PARTIAL pkt %d l%2d %s-%6d-%02d-%02d pvn ?", pkterr, buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            }
            break;
        case ePktErrRxdVarEndingSegPacketWithEmptyAssemblyBuf: // received endspan packet with empty assembly buf IN VARIABLE FRAME
            kprMutex.lock();printf ("dTu sDu pkterr VAR rxd endspan pkt with empty rxassembly buf l%2d %s-%6d-%02d-%02d pvn ?",buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            m_PktErrRxdVarEndingSegPacketWithEmptyAssemblyBuf++; // received continuing packet with empty assembly buf IN VARIABLE FRAME
            if ( packetInfoMib.m_Require_Incomplete_Packet_Delivery_To_User_At_Receiving_End == eTrue)
            {
                kprMutex.lock();printf ("dTu sDu PARTIAL pkt %d l%2d %s-%6d-%02d-%02d pvn ?", pkterr, buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            }
            break;
        case eMapaErrRxdVarEndingSegMapaWithEmptyAssemblyBuf:
            kprMutex.lock();printf ("dTu sDu MAPAerr VAR rxd endspan MAPA with empty rxassembly buf l%2d %s-%6d-%02d-%02d pvn ?",buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            m_MapaErrRxdVarEndingSegMapaWithEmptyAssemblyBuf++; // received ending MAPA with empty assembly buf IN VARIABLE FRAME
            if ( global_Require_Incomplete_MAPA_Delivery_To_User_At_Receiving_End == eTrue ) // mapa 
            {
                kprMutex.lock();printf ("dTu sDu PARTIAL MAPA %d l%2d %s-%6d-%02d-%02d pvn ?", pkterr, buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            }
            break;

        case eMapaErrRxdVarConstRule111WithNonEmptyAssemblyBuf: // received ANYTHING MAPA with 111 constRule with NONempty assembly buf IN VARIABLE FRAME
            kprMutex.lock();printf ("dTu sDu MAPAerr VAR rxd 111 MAPA with NONempty rxassembly buf l%2d %s-%6d-%02d-%02d pvn ?",buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            m_MapaErrRxdVarConstRule111WithNonEmptyAssemblyBuf++; // received starting MAPA with NONempty assembly buf IN VARIABLE FRAME
            if ( global_Require_Incomplete_MAPA_Delivery_To_User_At_Receiving_End == eTrue ) // mapa 
            {
                kprMutex.lock();printf ("dTu sDu PARTIAL 111 MAPA %d l%2d %s-%6d-%02d-%02d pvn ?", pkterr, buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            }
            break;
        case eDumpingCurrentRxAssemblyBufDueToRxdSdlsError: // received ANYTHING with an SDLS error
            kprMutex.lock();printf ("dTu sDu rxdSDLSerr with NONempty rxassembly buf l%2d %s-%6d-%02d-%02d pvn ?",buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            m_SdlsErrRxdWithNonEmptyAssemblyBuf++; // received starting MAPA with NONempty assembly buf IN VARIABLE FRAME
            if ( global_Require_Incomplete_MAPA_Delivery_To_User_At_Receiving_End == eTrue ) // mapa 
            {
                kprMutex.lock();printf ("dTu sDu PARTIAL 111 MAPA %d l%2d %s-%6d-%02d-%02d pvn ?", pkterr, buflen, m_map_PHYSCHANptr->m_Name.c_str(), m_map_MASTER_CHANNEL_ID, m_map_VCID, m_map_MAPID); seedata(buf, buflen); printf("\n"); fflush(stdout);kprMutex.unlock();
            }
            break;
    }
    m_RxAssemblyIndex[sqc0exp1] = 0; // RESET m_RxAssemblyBuf index to empty
}
bool kmapid::mapBuildAndTxTruncatedFrame ( unsigned char *rawData, int lagmcid, int lvcid, int lmapid) // below kvcid because it uses my_parentVcid
{
    bool goodtx = false;
    unsigned char lframe[MAX_FRAME_SIZE] ;
    int truncatedFrameLen = m_myVcidParent->m_truncatedFrameTotalLength; // mib parameter is total len. subtract 5 octets for 4-octet primary header and 1 octet tfdf header
    int lversion = lagmcid >> 16;
    int lscid = lagmcid & 0xff;
    int ldest_src = (lscid == global_MY_SPACECRAFT_ID) ? 0 : 1; // if the scid is MY scid then set to 0(source) else set to 1(destination)

    makeTransferFrameHeaderNoLen (lframe, lversion, lscid, ldest_src, lvcid, lmapid, 1, /*remaining parameters are just placeholders*/ 0,0,0,0,0ll); // 1 in endOfTransferFrameHeader means it's a truncated frame
    memcpy ( &lframe[4], rawData, truncatedFrameLen - 4); // truncated frame length is total lengh so subtract header length
    //
    // no IZ, OCF, security headers, or FECF
    //
    // grab physical channel tx mutex, transmit using physchan socket, release physchan mutex
    m_map_PHYSCHANptr->lockPhyschanTxLock();
    kprMutex.lock();printf ( "      Ready to txoat truncated length %d: ", truncatedFrameLen ); seedata ( lframe, truncatedFrameLen ); printf ( "\n" );fflush(stdout);kprMutex.unlock();
    int nb = m_map_PHYSCHANptr->m_txsock.write ( lframe, truncatedFrameLen, m_map_PHYSCHANptr->m_multicast_addr, m_map_PHYSCHANptr->m_TXport ); // write from here
    //klmq sleep(KLMTXDELAY);
    m_map_PHYSCHANptr->unlockPhyschanTxLock();

    if ( nb != truncatedFrameLen )
    {
        fprintf ( stderr, "mapBuildAndTxTruncatedFrame:  socket write error, nb=%d, nbytes=%d -- %s\n", nb, truncatedFrameLen, m_map_PHYSCHANptr->m_txsock.get_syserrstr() );
        fflush ( stderr );
    }
    else
    {
        goodtx = true;
    }
    // does truncated frame reset the milliseconds-between-frames-from-a-vcid timer? on mine it does.
    m_myVcidParent->resetVcidOidTimer();
    return goodtx; // successful tx?
}
// TWO QUEUE SOLUTION removing first-octet QoS
// ALL IDLE FILLING is done before calling tx()
// assumes m_constRules construction rules have already been set
// OCF data & length is ALREADY IN MAP 'thisframe' member
// assumes appropriate Queue mutex is already locked
//
bool kmapid::TXtoQueue( int txBypassFlag, const char *status ) // TODO eliminate status 
{
    int tfdfHeaderAndDataLen;
    unsigned char tfdfHeaderAndData[MAX_FRAME_SIZE];

    // get ocf with each tx since there will always be room for it if it's there
    //unsigned char lizData[MAX_INSERT_ZONE_SIZE];
    //int lizLen = MAX_INSERT_ZONE_SIZE;
    bool goodappend = false;
    int lheaderlen = m_permapheaderLen;
    klmprintf("TXtoQueue @%lld Qos=%d constRules %d %s\n",globalUsTimeNow,txBypassFlag, m_constRules,status);fflush(stdout);
    klmprintf("const %d %s %s \n",m_constRules,crstr[m_constRules],status);fflush(stdout);
#ifdef NEWMAKETFDFHEADER
    lheaderlen = makeTFDFheader( tfdfHeaderAndData, m_constRules, m_map_UslpProtocolIdSupported, m_mapfhplvo);
    klmprintf("klmdebug newtf map %d headerlen %d m_copyToOutputIndex %d\n",m_map_MAPID, lheaderlen, m_copyToOutputIndex);fflush(stdout);
#else
    //
    // make permapheader directly with m_constRules and fhp/lvo
    //
    mbf.putAddr(m_permapheader);
    mbf.put(0,3,m_constRules); // set octet stream construction rules
    if ( m_fixedlen ) // fixed length frames need FHP or LVO, not variable frames
    {
        // point at fhplvo offset in header
        mbf.putAddr(&m_permapheader[m_fhplvoOffset]);
        mbf.put(0,16,m_mapfhplvo); // set octet stream construction rules
    }
    klmprintf("klmdebug map %d headerlen %d m_copyToOutputIndex %d\n",m_map_MAPID, lheaderlen,m_copyToOutputIndex);fflush(stdout);
    memcpy(tfdfHeaderAndData,m_permapheader,lheaderlen);
#endif // NEWMAKETFDFHEADER
    //
    // copy header and data into headerAndDataToTx
    //
    memcpy(&tfdfHeaderAndData[lheaderlen],m_TxAssemblyBuf,m_copyToOutputIndex); 
    tfdfHeaderAndDataLen = lheaderlen + m_copyToOutputIndex; 
    //////////////////////////////////////////////////////
    //
    // put this tfdfHeaderandData into appropriate queue based on QoS
    //
    //////////////////////////////////////////////////////
    if ( txBypassFlag == eSequenceControlled ) // pass in this value because you may hafta be transmitting because of a changed one with a half-full-buffer
    {
        goodappend = m_qSeqCtrlTfdfs->append(tfdfHeaderAndData,tfdfHeaderAndDataLen);
    }
    else // 
    {
        goodappend = m_qExpeditedTfdfs->append(tfdfHeaderAndData,tfdfHeaderAndDataLen); 
    }
    if ( goodappend )
    {
        klmprintf("txtoq sq0exp1=%d apnd %d SUCCES ",txBypassFlag, tfdfHeaderAndDataLen);
    }
    if ( txBypassFlag == eSequenceControlled ) // pass in this value because you may hafta be transmitting because of a changed one with a half-full-buffer
    {
        kprMutex.lock(); printf("txtoq klmq sq0exp1=%d apnd %d %s ",txBypassFlag, tfdfHeaderAndDataLen,goodappend?"SUCCES":"failed"); seedata(tfdfHeaderAndData,tfdfHeaderAndDataLen);printf("> entries %ld\n",m_qSeqCtrlTfdfs->get_packet_count());fflush(stdout); kprMutex.unlock();
    }
    else
    {
        kprMutex.lock(); printf("txtoq klmq sq0exp1=%d apnd %d %s ",txBypassFlag, tfdfHeaderAndDataLen,goodappend?"SUCCES":"failed"); seedata(tfdfHeaderAndData,tfdfHeaderAndDataLen);printf("> entries %ld\n",m_qExpeditedTfdfs->get_packet_count());fflush(stdout);kprMutex.unlock();
    }
    // kprMutex.lock();printf("txo %s added len %d tfdf2Q <",status,tfdfHeaderAndDataLen);seedata(tfdfHeaderAndData,tfdfHeaderAndDataLen);printf("> entries %ld\n",m_qSeqCtrlTfdfs->get_packet_count());fflush(stdout);kprMutex.unlock();

    //
    // reset tx assembly buffer variables
    //
    m_txBufStartsWithContinuation = false; // just cleared the tx buffer
    m_usTimeToTransmitStartedTfdf = FOREVER_IN_THE_FUTURE ; // just emptied your tfdf
    m_copyToOutputIndex = 0;
    m_mapfhplvo = NO_VALUE; // no-value flag since all-ones and all-ones-minus-one are legal
    m_constRules = NO_VALUE;  // no-value flag (legal values are really only 0-7 but being consistent here)
    m_completeInbuf = false;
    m_beginSpan = false;
    m_middleSpan = false;
    m_endSpan = false;
    return goodappend;
}
// TWO-QUEUE solution
//
// there will be NO idle filling here - headerAndDataToTx is a TFDF (complete with tfdf header) that comes complete from the queue
//
bool kmapid::TXfromQueue( int sequenceControlled0expedited1, unsigned char *headerAndDataToTx, int headerAndDataLen, const char *status ) // TODO eliminate status 
{
    klmprintf("TXfromQueue len %d %s \n",headerAndDataLen,status);fflush(stdout);
    // get ocf with each tx since there will always be room for it if it's there
    unsigned char lizData[MAX_INSERT_ZONE_SIZE];
    int lizLen = MAX_INSERT_ZONE_SIZE;
    unsigned char locfData[MAX_OCF_LENGTH];
    int locfDataLen;
    int ltxBypassFlag;

    bool goodappend = false;
    //
    // set ltxBypassFlag
    //
    if ( sequenceControlled0expedited1 == eSequenceControlled )
    {
        ltxBypassFlag = 0;
    }
    else // assume eExpedited
    {
        ltxBypassFlag = 1;
    }

    //
    // get iz len
    //
    m_map_PHYSCHANptr->getInsertZone(lizData, &lizLen);
    // handle IZ on vcid level - disallow IZ if vcid frame type is variable or if physchan is false
    if ( m_map_PHYSCHANptr->m_Presence_of_Isochronous_Insert_Zone == eFalse || m_myVcidParent->m_vcid_Transfer_Frame_Type == eVariable )
    {
        lizLen = 0; // NO INSERT ZONE in this case
    }
    //
    // get OCF
    //
    m_myVcidParent->getVcidOcfBuf(locfData,&locfDataLen); // mutex-get this VCID's ocf (it's going to the master channel ocf service anyway)
    // feed ocf to physchan OID frame txer
    //
    // get FECF TODO
    //
    // now put everything into the uslp variables, build the frame, and tx
    //
    // have the physical channel transmit the frame
    //fastbit
    int lfirstOctetAfterVcCounters = makeTransferFrameHeaderNoLen( fastbitTxFrame, 
            m_map_PHYSCHANptr->m_Transfer_Frame_Version_Number,
            m_map_Spacecraft_ID,
            m_myVcidParent->m_source0Destination1,
            m_myVcidParent->m_VCID,
            m_map_MAPID,
            0, // endOfTransferFrameHeader
            ltxBypassFlag,
            0, // here this will always be 0(user data) m_protocolCommandControlFlag, // protocolCommandControlFlag 0=user data 1=protocol data
            locfDataLen==0?0:1, // ocfFlag - int in hdr
            m_myVcidParent->getVcFrameCounterOctets(ltxBypassFlag), // vcSeqCounterOctets
            m_myVcidParent->getVcFrameCounterAndInc(ltxBypassFlag)// vcSequenceCount // fastbit
            );
    // int buildParamFrameAddLen(unsigned char *fp, int offset,  // output frame and offset of first octet past frame header and vc frame counter to start adding the rest of the frame to
    // 																	bool izflag, int izlen, unsigned char *izdata,  // whether and what iz to add
    // 																	bool schdrflag, int schdrlen, unsigned char *schdrdata,  // whether and what security header to add
    // 																	int tfdflen, unsigned char *tfdfdata,  // what transfer frame data field (including TFDF header) to add
    // 																	bool sctrlrflag, int sctrlrlen, unsigned char *sctrlrdata,  // whether and what security trailer to add
    // 																	bool ocfflag, int ocflen, unsigned char *ocfdata,  // whether and what ocf data to add
    //																	bool fecfflag, int fecflen, unsigned char *fecfdata) // whether and what fecf data to add
    int totalFastbitFrameLen = buildParamFrameAddLen(fastbitTxFrame, 
            lfirstOctetAfterVcCounters, 
            (m_map_PHYSCHANptr->m_pc_Transfer_Frame_Type == eFixed && m_map_PHYSCHANptr->m_Presence_of_Isochronous_Insert_Zone == ePresent)?true:false, // iz flag
            lizLen, 
            lizData, 
            (m_myVcidParent->m_PresenceOfSpaceDataLinkSecurityHeader == ePresent)?true:false, // sc hdr flag
            m_myVcidParent->m_LengthOfSpaceDataLinkSecurityHeader, 
            m_myVcidParent->m_spaceDataLinkSecurityHeader, 
            headerAndDataLen,
            headerAndDataToTx,
            (m_myVcidParent->m_PresenceOfSpaceDataLinkSecurityTrailer == ePresent)?true:false, // sc trlr flag
            m_myVcidParent->m_LengthOfSpaceDataLinkSecurityTrailer, 
            m_myVcidParent->m_spaceDataLinkSecurityTrailer, 
            m_myVcidParent->m_vc_include_OCF, // ocf flag
            locfDataLen, 
            locfData, 
            (m_map_PHYSCHANptr->m_Presence_of_Frame_Error_Control == ePresent)?true:false, // fecf flag
            m_map_PHYSCHANptr->m_Frame_Error_Control_Length, 
            m_map_PHYSCHANptr->m_fecfData);
    //fastbit
    // fastbit
    kprMutex.lock();printf("hdr: f <");seedata(fastbitTxFrame,totalFastbitFrameLen);printf(">\n");fflush(stdout); kprMutex.unlock();
    int lreps;
    if ( ltxBypassFlag == eSequenceControlled )
    {
        lreps = m_myVcidParent->m_Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_service_data_on_the_Sequence_Controlled_Service; // limited by physchan repetitions parameter
    }
    else 
    {
        lreps = m_myVcidParent->m_RepetitionsValueUNLIMITEDbyPhyschanValue; // unlimited by physical channel for expedited frames
    }
    m_map_PHYSCHANptr->txFrame ( fastbitTxFrame,totalFastbitFrameLen, lreps );
    // fastbit
    //
    // reset tx assembly buffer variables
    //
    // klm918 decrementedUponGet() m_myVcidParent->decrementMCidOcfDeliveryCount(); // decrement the delivery count of the OCF since you may have just delivered it
    m_myVcidParent->resetVcidOidTimer(); // txed on this vcid; reset its timeout and the OID timeout
    // NO resetting of parameters because we're transmitting from the queue
    // m_txBufStartsWithContinuation = false; // just cleared the tx buffer
    // m_copyToOutputIndex = 0;
    // m_mapfhplvo = NO_VALUE; // no-value flag since all-ones and all-ones-minus-one are legal
    // m_constRules = NO_VALUE;  // no-value flag (legal values are really only 0-7 but being consistent here)
    // m_completeInbuf = false;
    // m_beginSpan = false;
    // m_middleSpan = false;
    // m_endSpan = false;
    return goodappend;
}
/*
   bool kmapid::TX( const char *status ) // TODO eliminate status 
   {
   unsigned char headerAndDataToTx[MAX_FRAME_SIZE];
   int headerAndDataLen;

   unsigned char lizData[MAX_INSERT_ZONE_SIZE];
   int lizLen = MAX_INSERT_ZONE_SIZE;
// get ocf with each tx since there will always be room for it if it's there
unsigned char locfData[MAX_OCF_LENGTH];
int locfDataLen;

bool goodappend = false;
#ifdef NEWMAKETFDFHEADER
makeTFDFheader( m_permapheader, m_constRules, m_map_UslpProtocolIdSupported, m_mapfhplvo);
#else
//
// make permapheader directly with m_constRules and fhp/lvo
//
mbf.putAddr(m_permapheader);
mbf.put(0,3,m_constRules); // set octet stream construction rules
if ( m_fixedlen ) // fixed length frames need FHP or LVO, not variable frames
{
// point at fhplvo offset in header
mbf.putAddr(&m_permapheader[m_fhplvoOffset]);
mbf.put(0,16,m_mapfhplvo); // set octet stream construction rules
}
#endif // NEWMAKETFDFHEADER
klmprintf("::TX ready const %d %s %s \n",m_constRules,crstr[m_constRules],status);fflush(stdout);
klmprintf("klmdebug map %d headerlen %d m_copyToOutputIndex %d\n",m_map_MAPID, m_permapheaderLen,m_copyToOutputIndex);fflush(stdout);
// get iz len
m_map_PHYSCHANptr->getInsertZone(lizData, &lizLen);
//
// get OCF
//
m_myVcidParent->getVcidOcfBuf(locfData,&locfDataLen); // mutex-get this VCID's ocf (it's going to the master channel ocf service anyway)
//
// handle IZ on vcid level - disallow IZ if vcid frame type is variable or if physchan is false
//
if ( m_map_PHYSCHANptr->m_Presence_of_Isochronous_Insert_Zone == eFalse || m_myVcidParent->m_vcid_Transfer_Frame_Type == eVariable )
{
lizLen = 0; // NO INSERT ZONE in this case
}
//
// copy header and data into headerAndDataToTx
//
memcpy(headerAndDataToTx,m_permapheader,m_permapheaderLen);
memcpy(&headerAndDataToTx[m_permapheaderLen],m_TxAssemblyBuf,m_copyToOutputIndex);
headerAndDataLen = m_permapheaderLen + m_copyToOutputIndex;

klmprintf("::TX headerAndDataLen = %d\n",headerAndDataLen);fflush(stdout);
//
// now put everything into the uslp variables, build the frame, and tx
//
// fastbit
int lfirstOctetAfterVcCounters = makeTransferFrameHeaderNoLen( fastbitTxFrame, 
m_map_PHYSCHANptr->m_Transfer_Frame_Version_Number,
m_map_Spacecraft_ID,
m_myVcidParent->m_source0Destination1,
m_myVcidParent->m_VCID,
m_map_MAPID,
0, // endOfTransferFrameHeader
m_txBypassFlag,
0, // here this will ALWAYS be 0(user data) m_protocolCommandControlFlag, // protocolCommandControlFlag 0=user data 1=protocol data
locfDataLen==0?0:1, // ocfFlag - int in hdr
m_myVcidParent->getVcFrameCounterOctets(m_txBypassFlag), // vcSeqCounterOctets
m_myVcidParent->getVcFrameCounterAndInc(m_txBypassFlag)// vcSequenceCount // fastbit
);
// int buildParamFrameAddLen(unsigned char *fp, int offset,  // output frame and offset of first octet past frame header and vc frame counter to start adding the rest of the frame to
// 																	bool izflag, int izlen, unsigned char *izdata,  // whether and what iz to add
// 																	bool schdrflag, int schdrlen, unsigned char *schdrdata,  // whether and what security header to add
// 																	int tfdflen, unsigned char *tfdfdata,  // what transfer frame data field (including TFDF header) to add
// 																	bool sctrlrflag, int sctrlrlen, unsigned char *sctrlrdata,  // whether and what security trailer to add
// 																	int ocflen, unsigned char *ocfdata,  // whether and what ocf data to add
//																	bool fecfflag, int fecflen, unsigned char *fecfdata) // whether and what fecf data to add

int totalFastbitFrameLen = buildParamFrameAddLen(fastbitTxFrame, 
        lfirstOctetAfterVcCounters, 
        (m_map_PHYSCHANptr->m_pc_Transfer_Frame_Type == eFixed && m_map_PHYSCHANptr->m_Presence_of_Isochronous_Insert_Zone == ePresent)?true:false, // iz flag
        lizLen, 
        lizData, 
        (m_myVcidParent->m_PresenceOfSpaceDataLinkSecurityHeader == ePresent)?true:false, // schdr flag
        m_myVcidParent->m_LengthOfSpaceDataLinkSecurityHeader, 
        m_myVcidParent->m_spaceDataLinkSecurityHeader, 
        headerAndDataLen, // NO NEED to skip first octet because since this isn't coming from the QUEUE it doesn't have the bypass indicator octet in it
        headerAndDataToTx, // NO NEED to skip first octet because since this isn't coming from the QUEUE it doesn't have the bypass indicator octet in i&t
        (m_myVcidParent->m_PresenceOfSpaceDataLinkSecurityTrailer == ePresent)?true:false, // sctrlr flag
        m_myVcidParent->m_LengthOfSpaceDataLinkSecurityTrailer, 
        m_myVcidParent->m_spaceDataLinkSecurityTrailer, 
        m_myVcidParent->m_vc_include_OCF, // ocf flag
        locfDataLen, 
        locfData, 
        (m_map_PHYSCHANptr->m_Presence_of_Frame_Error_Control == ePresent)?true:false, // fecf flag
        m_map_PHYSCHANptr->m_Frame_Error_Control_Length, 
        m_map_PHYSCHANptr->m_fecfData);
//fastbit
kprMutex.lock();printf("hdr: ::TX f <");seedata(fastbitTxFrame,totalFastbitFrameLen);printf(">\n");fflush(stdout); kprMutex.unlock();
int lreps;
if ( m_txBypassFlag == eSequenceControlled )
{
    lreps = m_myVcidParent->m_Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_service_data_on_the_Sequence_Controlled_Service; // limited by physchan reps parameter
}
else
{
    lreps = m_myVcidParent->m_RepetitionsValueUNLIMITEDbyPhyschanValue; // unlimited by physchan reps param for expedited frames
}
m_map_PHYSCHANptr->txFrame ( fastbitTxFrame, totalFastbitFrameLen, lreps );
// fastbit
//
// reset tx assembly buffer variables
//
m_txBufStartsWithContinuation = false; // just cleared the tx buffer
m_copyToOutputIndex = 0;
m_mapfhplvo = NO_VALUE; // no-value flag since all-ones and all-ones-minus-one are legal
m_constRules = NO_VALUE;  // no-value flag (legal values are really only 0-7 but being consistent here)
m_completeInbuf = false;
m_beginSpan = false;
m_middleSpan = false;
m_endSpan = false;
return goodappend;
}
*/
/*
   void kvcid::txVcidIdle( kphysicalChannel *lptrphyschan) // nothing on this vcid to tx and it's been too long since you txed something
   {
   unsigned char locfData[MAX_OCF_LENGTH];
   int locfDataLen;

   unsigned char izData[MAX_INSERT_ZONE_SIZE];
   int izLen = MAX_INSERT_ZONE_SIZE;

   unsigned char lidle[MAX_FRAME_SIZE];	

   klmprintf("txVcidIdle vcid %d idle \n",m_VCID);fflush(stdout);

   kmapid *lptrmapid = m_mapmap.begin()->second; // point at your first mapid

   int lTotalTfdfLen = lptrmapid->m_maxTotalHeaderlessDataFieldOctets + lptrmapid->m_permapheaderLen; // this is what the total TFDF len should be (assumes one header and one headerless datafield)

   idleFillHere(lidle, lTotalTfdfLen, m_vcid_pcOidData ); // header with idle data

// get IZ data and len
lptrphyschan->getInsertZone(izData, &izLen);

// handle IZ on vcid level - disallow IZ if vcid frame type is variable or if physchan is false
if ( lptrphyschan->m_Presence_of_Isochronous_Insert_Zone == eFalse || m_vcid_Transfer_Frame_Type == eVariable )
{
izLen = 0; // NO INSERT ZONE in this case
}
lptrphyschan->uslptx.putEverythingButDatafieldHeaderAndData
(
lptrphyschan->m_Transfer_Frame_Version_Number,   // version_id - same on all physchans - table 5-2, note 1 4/26/2016 spec
lptrmapid->m_map_Spacecraft_ID,    // scid,
m_source0Destination1,   // dest_src, 0=scid is SOURCE of frame, 1=scid is DEST of the frame based on whether VCID's MCID's spacecraftId = global_MY_SPACECRAFT_ID
0,   // dest_src, 0=scid is SOURCE of frame, 1=scid is DEST of the frame
m_VCID,    // vcid,
lptrmapid->m_map_MAPID,   // mapid,
0,   // eohdr,
m_txBypassFlag,   // bypassFlag ,
0,   // commandControlFlag - if idle frame it won't have come from a prox-1 frame so zero it out because there's nothing to have copied
0,   // reserveSpares,
locfDataLen,    // ocfLen,
locfData,   // *ocfData,
getVcFrameCounterOctets(lptrmapid->m_txBypassFlag),   // vcFrameCountOctets,
getVcFrameCounterAndInc(lptrmapid->m_txBypassFlag),   // vcFrameCounter,
izLen,    // insert zone len
izData,   // *insert zone data
m_LengthOfSpaceDataLinkSecurityHeader,   // secHdrLen,
m_spaceDataLinkSecurityHeader, // *secHdrData,
m_LengthOfSpaceDataLinkSecurityTrailer,                    // secTrlrLen,
m_spaceDataLinkSecurityTrailer, // *secTrlrData,
lptrphyschan->m_Frame_Error_Control_Length,  // fecfLen,
lptrphyschan->m_fecfData // *fecfData
);
lptrphyschan->uslptx.putDatafieldHeaderAndData ( lidle, lTotalTfdfLen );
lptrphyschan->uslptx.buildFrame(); // build an UNtruncated frame
klmprintf("txing VCID %d IDLE framelen %d \n",m_VCID,lptrphyschan->uslptx.getTotalFrameLen());fflush(stdout);
lptrphyschan->txFrame ( lptrphyschan->uslptx.getframe(),lptrphyschan->uslptx.getTotalFrameLen() );
// extend when to tx next timeout vcid frame
resetVcidOidTimer(); // txed on this vcid
}
*/
//
// THIS is where m_Maximum_delay_in_milliseconds_between_releases_of_frames_of_the_same_VC is used.
// after a tx, reset the VCID's timer to be the max-per-vcid delay to tx again
//
//
void kvcid::resetVcidOidTimer(void)
{
    /* for timed delivery
       struct timeval tv;
       gettimeofday(&tv,NULL);
       globalUsTimeNow = tv.tv_sec;
       */
    // per map time-to-release-started-tfdf must be done per map
#ifdef DOPRINTFS
    // 	klmprintf("      resetVcidOidTimer vc %d Maxdelay %d sets gtn to %d\n",m_VCID,  m_Maximum_delay_in_milliseconds_between_releases_of_frames_of_the_same_VC, globalUsTimeNow);fflush(stdout);
#endif // DOPRINTFS
    if ( m_timedVcidReleasesFlag )
    {
        m_vcidUsTimeToTxMinTimeBetweenVcidFrames = globalUsTimeNow + (long long)m_Maximum_delay_in_milliseconds_between_releases_of_frames_of_the_same_VC;
    }
}
class mibclass:public PThread
{
    public:

        std::map <String,kphysicalChannel *>::iterator m_physchanit; // for scanning through physical channels
        std::map<int, kmasterChannel *>::iterator m_mc_it; // for scanning through master channels
        std::map<int, kvcid *>::iterator m_vcidit; // for scanning through virtual channels
        std::map<int, kmapid *>::iterator m_mapit; // for scanning through map ids

        bool verifyMAP_ID ( String & physchan, int mc_id, int vcid,int map_id );
        bool verifyVCID ( String & physchan, int mc_id, int vcid );
        bool verify_MC_ID ( String & physchan, int mc_id );
        bool verifyPhysChan ( String & physchan );
        void (*m_mibDeliverFn)(unsigned char *data, int datalen, int type, String physchan, int tfvn, int scid, int vcid, int mapid);
        void (*m_mibGIVEWHOLEFRAMEFN)(unsigned char *data, int datalen);
        void mibGetMcOcf ( String physchan, int tfvn, int scid, unsigned char *ocf, int *ocflen)
        {
            int agmcid = (65536 * tfvn) + scid;
            pcmap[physchan]->m_MCmap[agmcid]->getMCidOcfBuf(ocf,ocflen,eFixed); // pass in fixed or variable
        }
        //mibRxThread *m_rxthread;

        int m_pvn; // for scanning pvns
        int m_triedphyschans;
        int m_triedMCs;
        int m_triedvcids;
        int m_triedmaps;
        int m_triedpvns; // reset but not EVERY time
        int dummyTxSDU_ID;

        sem_t m_gotData_sem;
        std::map <String,kphysicalChannel *> pcmap;
        void kassignValids ( String & value,int oneMoreThanMaximumValue,bool * boollist );
        kmapid * findMap ( String physchan, int MCid, int vcid,int mapid );
        void parse10params ( char * line ) ;
        char * findNonNum ( char * cp );
        char * findNum ( char * cp );
        char * findWhitespace ( char * cp );
        char * skipWhitespace ( char * cp );
        int kintval ( String & str );
        int enumPresentAbsent ( String & par );
        int enumTrueFalse ( String & par );
        char * strPresentAbsent ( int pa );
        char * strFixedVariable ( int fv );
        char * strTrueFalse ( int tf );
        const char * strServiceData ( int fv );
        int enumFixedVariable ( String & par );
        int enumServiceData ( String & par );
        bool parseline ( char * line );
        void dumpPhysicalChannelMap ( void );
        void dumpMasterChannelMap ( std::map <int,kmasterChannel *> & mcmap );
        void dumpVcidMap ( std::map<int,kvcid *> & vcidmap );
        void dumpMapMap ( std::map<int,kmapid *> & mapmap );
        void dumpPacketMib ( void );
        void dumpConfigs ( void );

        char m_insertZoneData[MAX_FRAME_SIZE];
        int m_insertZoneLen;

        void resetVcidSeqCtrlFrameCounter(String physchan, int tfvn, int scid, int vcid, long long resetToThisValue)
        { 
            int agmcid = (65536 * tfvn) + scid;
            pcmap[physchan]->m_MCmap[agmcid]->m_vcidmap[vcid]->m_vcSeqCtrlCounter = resetToThisValue;
        }

    private:
        //////////////////////////////////////////////////////////////////////////////////////////////////////
        // for parsing
        //////////////////////////////////////////////////////////////////////////////////////////////////////
#ifndef PTFBITFIELDREWRITTEN
        bool mibParseFrame(kphysicalChannel *lptrphyschan, unsigned char *rxbuf, int rxlen, bool *isTruncatedFrame, bool *isOIDframe); // parse frame here because you need to have access to mib data to do it (secHdr secTrlr len are per-vcid)
#endif // PTFBITFIELDREWRITTEN
        void seeEverything ( void );

        int m_version_id;                 // 4 bits  @ 0 version num
        int m_scid;                       // 16 bits @ 4 spacecraft id
        int m_dest_src;                   // 1 bit   @ 20 src/dest id
        int m_vcid;                       // 6 bits  @ 21 vcid
        int m_mapid;                      // 4 bits  @ 27 mapid
        int m_endOfTransferHeaderFlag;                      // 1 bit   @ 31 end of tf header flag
        int m_totalFrameLen;              // 16 bits @ 32 total frame length (actually contains total-octets-minus-one
        int m_bypassFlag ;                // 1 bit   @ 48 bypass flag 4.1.2.9.1.1
        int m_reserveSpares;              // 3 bits  @ 49 set to 0 as per 4.1.2.9.2
        int m_ocfLen;                     // 1 bit @52  set to 0 if no ocf, set to ocf length if ocf is present
        int m_vcFrameCountOctets;         // 3 bits  @ 53 0-7 for 0-to-7 octets
        int m_vcFrameServiceCounter;      // up to 7 octets of rollover counts for frame service

        int m_primaryHeaderLen;           // current length of primary header
        int m_ocfPresent;                 // taken from incoming frame
        unsigned char m_ocfData[MAX_OCF_LENGTH];     // 4 octets of ocf data plus nul

        // insert zone
        int m_izOffset; // opt insert zone
        int m_izLen;    // insert zone length
        unsigned char m_izData[MAX_ISOCHRONOUS_DATA_LENGTH]; // no more than 256 octets

        // security header offset
        int m_secHdrOffset;
        int m_secHdrLen;
        unsigned char m_secHdrData[MAX_SECURITY_HEADER_DATA];

        // transfer frame data field header
        int m_dfHdrOffset;  // data field HEADER offset
        int m_dfHdrLen;     // data field HEADER length
        int m_constrRules;      // construction rules
        int m_protocolId;     // protocol identifier (saved in one int whether it's extended or not)
        int m_fhpLvo;         // first header pointer or last valid octet
        // transfer frame data field DATA
        int m_dfDataOffset; // data field DATA offset
        int m_dfDataOnlyLen;    // data field DATA length (does not include data field header)
        unsigned char m_dfDataOnly[MAX_FRAME_SIZE]; // headerless data in the data field

        // security trailer offset
        int m_secTrlrOffset;
        int m_secTrlrLen;
        unsigned char m_secTrlrData[MAX_SECURITY_TRAILER_DATA];

        // ocf offset
        int m_ocfOffset;
        //  m_ocfLen declared above

        // fecf offset
        int m_fecfOffset;
        int m_fecfLen;
        unsigned char m_fecfData[MAX_FECF_SIZE];

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////fastbit

        /*
           int m_version_id;                 // 4 bits  @ 0 version num
           int m_scid;                       // 16 bits @ 4 spacecraft id
           int m_dest_src;                   // 1 bit   @ 20 src/dest id
           int m_vcid;                       // 6 bits  @ 21 vcid
           int m_mapid;                      // 4 bits  @ 27 mapid
           int m_endOfTransferHeaderFlag;                      // 1 bit   @ 31 end of tf header flag
           int m_totalFrameLen;              // 16 bits @ 32 total frame length (actually contains total-octets-minus-one
           int m_bypassFlag ;                // 1 bit   @ 48 bypass flag 4.1.2.9.1.1
           int m_reserveSpares;              // 3 bits  @ 49 set to 0 as per 4.1.2.9.2
           int m_ocfLen;                     // 1 bit @52  set to 0 if no ocf, set to ocf length if ocf is present
           int m_vcFrameCountOctets;         // 3 bits  @ 53 0-7 for 0-to-7 octets
           int m_vcFrameServiceCounter;      // up to 7 octets of rollover counts for frame service

           int m_primaryHeaderLen;           // current length of primary header
           int m_ocfPresent;                 // taken from incoming frame
           */
        unsigned char ptfOcfData[MAX_OCF_LENGTH];     // 4 octets of ocf data plus nul
        unsigned char ptfTfdfData[MAX_FRAME_SIZE];     // tfdf data including tfdf header
        /*
        // insert zone
        int m_izOffset; // opt insert zone
        int m_izLen;    // insert zone length
        */
        unsigned char ptfIzData[MAX_ISOCHRONOUS_DATA_LENGTH]; // no more than 256 octets
        /*
        // security header offset
        int m_secHdrOffset;
        int m_secHdrLen;
        */
        unsigned char ptfSecHdrData[MAX_SECURITY_HEADER_DATA];
        /*

        // transfer frame data field header
        int m_dfHdrOffset;  // data field HEADER offset
        int m_dfHdrLen;     // data field HEADER length
        */
        int ptfConstrRules;      // construction rules
        int ptfProtocolId;     // protocol identifier (saved in one int whether it's extended or not)
        int ptfFhpLvo;         // first header pointer or last valid octet
        int ptfTfdfDataOnlyLen;    // data field DATA length (does not include data field header)
        unsigned char ptfTfdfDataOnly[MAX_FRAME_SIZE]; // headerless data in the data field

        /*
        // security trailer offset
        int m_secTrlrOffset;
        int m_secTrlrLen;
        */
        unsigned char ptfSecTrlrData[MAX_SECURITY_TRAILER_DATA];
        /*
        // ocf offset
        int m_ocfOffset;
        //  m_ocfLen declared above

        // fecf offset
        int m_fecfOffset;
        int m_fecfLen;
        */
        unsigned char ptfFecfData[MAX_FECF_SIZE];
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////fastbit

    public:
        // constructor
        mibclass() 
        {
            dummyTxSDU_ID = 0;
            sem_init ( &m_gotData_sem,0,0 );
            memset ( m_insertZoneData,0,MAX_FRAME_SIZE );
            m_insertZoneLen = 0;
            /*
               m_qToDo_mutex.lock();
               m_qToDo = new CircularPacketQueue ( sizeof(toDoEntry) * MAX_TODO_Q_ENTRIES); // make ocf circular queue
               m_qToDo_mutex.unlock();
               */
            //
            // assign endianness
            //
            endianlonglonglsbtomsb = ll_07lsbtomsb; // or some other if another endianness is required
            endianintegerlsbtomsb = i_03lsbtomsb; // or some other if another endianness is required
            m_mibGIVEWHOLEFRAMEFN = NULL;
            //klmq        klmprintf("1endianintegerlsbtomsb %p i_03lsbtomsb %p\n",endianintegerlsbtomsb,i_03lsbtomsb);fflush(stdout);
        }
        bool parseTransferFrameHeader (
                kphysicalChannel *lptrphyschan,
                unsigned char *fp, // pointer at octet 0 of the frame
                int rxframelen, // how big the calling function says the frame is
                int *version_id,
                int *spacecraftId,
                int *dest_src,
                int *vcid,
                int *mapid,
                int *endOfTransferFrameHeader,
                int *framelen,
                int *bypassFlag,
                int *protocolCommandControlFlag,
                int *ocfFlag,
                int *vcSeqCounterOctets,
                long long *vcSequenceCount, // actual sequence count (can't be more octets than vcSeqCounterOctets)
                int *firstOctetPastVcFrameCounters, // index
                bool *isTruncatedFrame,  // flag
                bool *isOidFrame // flag
                );
        void mibVcidMaxDelayBetweenReleasesOfSameVcidFramesTimeout(String pchan, int mcid, int vcid);
        /*
           bool addToDoQueueEntry(unsigned char *physchanstr,int mcid, int vcid, int mapid, int pvn, int what)
           {
           bool goodappend = true;
           m_qToDo_mutex.lock();
        // constuct an entry and add it to todoQ
        strncpy((char *)toDoEntry.physchanstr,(char *)physchanstr,sizeof(toDoEntry.physchanstr));
        toDoEntry.mcid = mcid;
        toDoEntry.vcid = vcid;
        toDoEntry.mapid = mapid;
        toDoEntry.pvn = pvn;
        toDoEntry.what = what;
        // get time. for now it's seconds
        struct timeval tv;
        gettimeofday(&tv,NULL);
        toDoEntry.when = tv.tv_sec; // one second resolution now
        // now add this entry to ToDoQueue
        goodappend = m_qToDo->append((unsigned char *)&toDoEntry,(long int)sizeof(toDoEntry)); // stuff todo
        m_qToDo_mutex.unlock();
        klmprintf("addToDoQueueEntry %s %d %d %d %d %d %d added %s\n",physchanstr,mcid,vcid,mapid,pvn,what,toDoEntry.when, goodappend?"ok":"fail"); fflush(stdout);
        return goodappend;
        }
        */
        void putGIVEWHOLEFRAMEFN( void (*thefn)(unsigned char *, int))
        {
            m_mibGIVEWHOLEFRAMEFN = thefn;
        }
        void mibPutDeliverFn( void (*thefn)(unsigned char *, int, int ), String physchan, int tfvn, int scid, int vcid, int mapid)
        {
            int agmcid = (65536 * tfvn) + scid;
            printf("TRYING TO deliverfn %p to %s/%d/%d/%d\n",thefn, physchan.c_str(),agmcid,vcid,mapid);fflush(stdout);
            if ( verifyMAP_ID ( physchan, agmcid, vcid,mapid ))
            {
                pcmap[physchan]->m_MCmap[agmcid]->m_vcidmap[vcid]->m_mapmap[mapid]->putDeliverFn(thefn);
                printf("deliverfn %p delivered to %s/%d/%d/%d\n",thefn, physchan.c_str(),agmcid,vcid,mapid);fflush(stdout);
            }
            else
            {
                printf("invalid tree for deliverfn %s/%d/%d/%d\n",physchan.c_str(),agmcid,vcid,mapid);fflush(stdout);
                exit(3);
            }
        }
        void killthisMibPutVcFrameDropper(String physchan, int tfvn, int scid, int vcid, int dropN, int dropEveryN ) // killthis it's pure debug to be able to drop N frames every N frames
        {
            int agmcid = (65536 * tfvn) + scid;
            printf("TRYING TO putFrameDropper to %s/%d/%d\n", physchan.c_str(),agmcid,vcid);fflush(stdout);
            if ( verifyVCID ( physchan, agmcid, vcid ))
            {
                pcmap[physchan]->m_MCmap[agmcid]->m_vcidmap[vcid]->killthisVcFrameDropper(dropN, dropEveryN);
            }
            else
            {
                printf("invalid tree for putFrameDropper %s/%d/%d\n",physchan.c_str(),agmcid,vcid);fflush(stdout);
                exit(3);
            }
        }
        void mibPutFarmFn( bool (*thefn)( int ), String physchan, int tfvn, int scid, int vcid)
        {
            int agmcid = (65536 * tfvn) + scid;
            if ( verifyVCID ( physchan, agmcid, vcid ))
            {
                pcmap[physchan]->m_MCmap[agmcid]->m_vcidmap[vcid]->putFarmFn(thefn);
                printf("deliverfn %p delivered to %s/%d/%d\n",thefn, physchan.c_str(),agmcid,vcid);fflush(stdout);
            }
            else
            {
                printf("invalid tree for deliverfn %s/%d/%d\n",physchan.c_str(),agmcid,vcid);fflush(stdout);
                exit(3);
            }
        }
        void readMibConfig ( char * filename )
        {
            FILE * fp = NULL;
            char line[65536];
            klmprintf("READING MIB CONFIG FILE %s\n",filename);fflush(stdout);
            if ( ( fp = fopen ( filename,"r" ) ) != NULL )
            {
                while ( !feof ( fp ) )
                {
                    fgets ( line,sizeof ( line ),fp );
                    if ( line[strlen ( line )-1] == '\n' )
                    {
                        line[strlen ( line ) - 1] = '\0';
                    }
                    if ( line[0] != '#' )
                    {
                        parseline ( line );
                    }
                }
            }
            //
            //
            //
            //
            //	after you've read the config file, calculate some values, do some propagation (frame type, oid data pointers) to subordinates, set some lengths (iz len = 0 if physchan type = variable)
            //
            //
            //
            // 
            for ( m_physchanit = pcmap.begin(); m_physchanit != pcmap.end(); m_physchanit++ )
            {
                kphysicalChannel *lphyschanptr = m_physchanit->second;
                //
                // parameters that trump other parameters (and affect m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets)
                //
                // set IZ len to 0 if physchan IZ not present (or of physchan frame type is variable)
                if ( lphyschanptr->m_pc_Transfer_Frame_Type == eVariable || lphyschanptr->m_Presence_of_Isochronous_Insert_Zone != ePresent ) // if variable PC frame type, IZ is forbidden (as per ed greenberg email, 2017/05/16)
                {
                    lphyschanptr->m_Isochronous_Insert_Zone_Length = 0; 
                    klmprintf("iz absented to zero since frame type is variable, as per ed greenberg email 05/16/2017\n"); fflush(stdout);
                }
                //
                // all MCID parameters
                //
                for ( m_mc_it = m_physchanit->second->m_MCmap.begin(); m_mc_it != m_physchanit->second->m_MCmap.end(); m_mc_it++)
                {
                    kmasterChannel *lptrMasterChannel = m_mc_it->second;
                    //
                    // propagate fixed-length frame type down from physchan to masterchan, trumping mibconfig 
                    //
                    if ( lphyschanptr->m_pc_Transfer_Frame_Type == eFixed) 
                    {
                        lptrMasterChannel->m_MC_Transfer_Frame_Type = eFixed; 
                    }

                    for ( m_vcidit = m_mc_it->second->m_vcidmap.begin(); m_vcidit != m_mc_it->second->m_vcidmap.end(); m_vcidit++ )
                    {
                        kvcid *lptrvcid = m_vcidit->second;
                        //
                        // propagate fixed-length frame type down from masterchan to vcid
                        //
                        if ( lptrMasterChannel->m_MC_Transfer_Frame_Type == eFixed ) 
                        {
                            lptrvcid->m_vcid_Transfer_Frame_Type = eFixed; // propagate fixed-length frame type down from masterchan to vcid, trumping mibconfig 
                        }
                        //
                        // propagate maximum frame length from physchan to vcid because you need it on vcid
                        //
                        lptrvcid->m_vcid_Maximum_Transfer_Frame_Length = lphyschanptr->m_pc_Transfer_Frame_Length; // propagate minimum frame length from master channel to virtual channel
                        //
                        // VCID parameters that trump other parameters (and affect m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets)
                        //
                        // vcid security header present
                        if ( lptrvcid->m_PresenceOfSpaceDataLinkSecurityHeader == eAbsent )
                        {
                            lptrvcid->m_LengthOfSpaceDataLinkSecurityHeader = 0;
                        }
                        // vcid security trailer present
                        if ( lptrvcid->m_PresenceOfSpaceDataLinkSecurityTrailer == eAbsent )
                        {
                            lptrvcid->m_LengthOfSpaceDataLinkSecurityTrailer = 0;
                        }
                        //
                        //	= ocf-included is based on frame type and inclusion flags.
                        //	- for speedy processing the regular vc_include_OCF flag is derrived from frame type and fixed/variable inclusion
                        int localOcfPossibleLen = 0; // assume 0 octet len unless allowed/required
                        lptrvcid->m_vc_include_OCF = false; // default to no
                        if ( lptrvcid->m_vcid_Transfer_Frame_Type == eFixed && lptrvcid->m_vcRequireFixedFrameInclusionOfOcf == eTrue )
                        {
                            lptrvcid->m_vc_include_OCF = true; // yes if fixed and requirefixed
                            localOcfPossibleLen = MAX_OCF_LENGTH; // assume 4 octet len unless prohibited
                        }
                        if ( lptrvcid->m_vcid_Transfer_Frame_Type == eVariable && lptrvcid->m_allowVariableFrameInclusionOfOcf == eTrue ) 
                        {
                            lptrvcid->m_vc_include_OCF = true; // yes if variable and allowvariable
                            localOcfPossibleLen = MAX_OCF_LENGTH; // assume 4 octet len unless prohibited
                        }
                        if ( lptrvcid->m_VcidFrameService || lptrvcid->m_VCID == 63 ) // no ocf in OID 
                        {
                            lptrvcid->m_vc_include_OCF = false; // make sure vcid frame service vcids and cop service vcids don't get OCFs distributed to them
                        }

                        // propagate physchan OID info to vcid
                        lptrvcid->m_vcid_pcOidData = lphyschanptr->m_pcOIDdata; // propagate PC oid info
                        //
                        // handle all map parameters
                        //
                        for ( m_mapit = m_vcidit->second->m_mapmap.begin(); m_mapit != m_vcidit->second->m_mapmap.end(); m_mapit++ )
                        {
                            kmapid *lptrmapid = m_mapit->second; 
                            //
                            // propagate vcid specified m_vc_maxMsDelayToReleaseTfdfOnceStarted down to the map subordinates. 
                            //  = timing calculations will be made at the map level 
                            //  - since every map has its own TFDF buffer that must 
                            //  - be emptied within the specified time
                            lptrmapid->m_map_maxMsDelayToReleaseTfdfOnceStarted_fromvc = lptrvcid->m_vc_maxMsDelayToReleaseTfdfOnceStarted;
                            //
                            //
                            // header len if 000-010 fhp/lvo used; if protocolid > 30, ext protocol id used
                            // 
                            lptrmapid->m_permapheaderLen = 1; // at least one
                            // go ahead and fill the map header with the protocol id. you CAN do that
                            // lptrmapid->mbf.putAddr(lptrmapid->m_permapheader);
                            // lptrmapid->mbf.put(3,5,lptrmapid->m_map_UslpProtocolIdSupported); // add in protocol id (parseline has already subtracted 31 from it)
                            // AND/OR directly into octet
                            lptrmapid->m_permapheader[0] &= 0xe0; // zero out lower 5 bits
                            lptrmapid->m_permapheader[0] |= lptrmapid->m_map_UslpProtocolIdSupported & 0x1f; // only allow lower 5 bits

                            lptrmapid->m_fhplvoOffset = lptrmapid->m_permapheaderLen;  // save fhplvo offset (may not need)
                            if ( lptrvcid->m_vcid_Transfer_Frame_Type == eFixed)  // 000,001,010
                            {
                                lptrmapid->m_permapheaderLen += 2; // header includes fhp or lvo if fixed len, not otherwise
                            }
                            //////////////////////////////////////////////////////////////////////////////////////////////////////
                            // get per-map tfdf length (NOT including header)
                            //////////////////////////////////////////////////////////////////////////////////////////////////////
                            // gotta allow for insert zone not being in variable length fields
                            int localIzLen = lphyschanptr->m_Isochronous_Insert_Zone_Length;
                            // 
                            // handle IZ on vcid level - disallow IZ if vcid frame type is variable or if physchan is false. assumes fixed/variable frametype has been propagated down from physchan to subordinates
                            //
                            if ( lphyschanptr->m_Presence_of_Isochronous_Insert_Zone == eFalse || lptrvcid->m_vcid_Transfer_Frame_Type == eVariable )
                            {
                                localIzLen = 0; // NO INSERT ZONE in this case
                            }
                            // 
                            // for fixed len frames, ocf is in every frame so always include it if VIRTUAL_CHANNEL_Inclusion_of_OCF_Required_Fixed_Length_Frames = True
                            // for variable len frames, ocf is OPTIONAL and you don't know WHEN you're going to get it (may get it halfway through building the frame), so subtract ocf len from MAXIMUM if VIRTUAL_CHANNEL_Inclusion_of_OCF_Allow_Variable_Length_Frames = true
                            // worst case, that'll have you building a non-ocf frame that's 4 octets shorter than it COULD have been. 
                            // at max frame len, 65536, that's 0.006% waste. TOTALLY worth it for the ease of coding and not having to handle the "what if i get ocf halfway through building the frame" situation (like a tfdf that leaves 2 octets, and then you get an OCF that now won't fit).
                            // 
                            lptrmapid->m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets = 
                                lptrvcid->m_vcid_Maximum_Transfer_Frame_Length     // VCID frame length (which may have been trumped by parent lengths)
                                - lptrvcid->m_LengthOfSpaceDataLinkSecurityHeader  // - MIB security header len
                                - lptrvcid->m_LengthOfSpaceDataLinkSecurityTrailer // - MIB security trailer len
                                - localIzLen                                       // - calculated insert zone length
                                - FRAME_PRIMARY_HEADER_OCTETS                      // - frame header len (if not truncated)
                                - lphyschanptr->m_Frame_Error_Control_Length       // - fecf length
                                - lptrmapid->m_permapheaderLen;                    // - tfdf header
                            // set all maps' var/fixed bools
                            // klmprintf("pc %s mc %d vcid %d frametype = %s  map %d mhl %d\n",lphyschanptr->m_Name.c_str(), m_mc_it->second->m_MC_ID, lptrvcid->m_VCID, (lptrvcid->m_vcid_Transfer_Frame_Type == eFixed)?"Fixed":"Varibl", lptrmapid->m_map_MAPID, lptrmapid->m_permapheaderLen);fflush(stdout);
                            lptrmapid->m_fixedlen = lptrvcid->m_vcid_Transfer_Frame_Type == eFixed ? true : false; // true if fixed, false if variable
                            if ( (lptrmapid->m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets - lptrvcid->getVcFrameCounterOctets(eSequenceControlled - localOcfPossibleLen)) <= 0 // no room if sequence controlled frame counter octets
                                    ||
                                    (lptrmapid->m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets - lptrvcid->getVcFrameCounterOctets(eExpedited) - localOcfPossibleLen) <= 0 // no room if expedited frame counter octets
                               )
                            {
                                klmprintf("ERROR - NO available TFDF data octets for map %s given max frame len of %d with primary hdr 7, MIB sec hdr %d trlr %d, IZ %d, (fco: seqCtrl %d or Exp %d), TFDF header %d, Fecf %d OcfPosssibleLen %d \n",
                                        lptrmapid->mapktree(),
                                        lptrvcid->m_vcid_Maximum_Transfer_Frame_Length,
                                        lptrvcid->m_LengthOfSpaceDataLinkSecurityHeader,
                                        lptrvcid->m_LengthOfSpaceDataLinkSecurityTrailer,
                                        localIzLen,
                                        lptrvcid->getVcFrameCounterOctets(eSequenceControlled),
                                        lptrvcid->getVcFrameCounterOctets(eExpedited),
                                        lptrmapid->m_permapheaderLen,
                                        lphyschanptr->m_Frame_Error_Control_Length,
                                        localOcfPossibleLen); 
                                fflush(stdout);
                                exit(1); // TODO handle this error
                            }
                            /*klmprintf(" ready maxheaderless (-fco/ocf) %d for map %s given max frame len of %d with primary hdr 7, MIB sec hdr %d trlr %d, IZ %d, (fco: seqCtrl %d or Exp %d), TFDF header %d, Fecf %d \n",
                              lptrmapid->m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets, 
                              lptrmapid->mapktree(),
                              lptrvcid->m_vcid_Maximum_Transfer_Frame_Length,
                              lptrvcid->m_LengthOfSpaceDataLinkSecurityHeader,
                              lptrvcid->m_LengthOfSpaceDataLinkSecurityTrailer,
                              localIzLen,
                              lptrvcid->getVcFrameCounterOctets(eSequenceControlled),
                              lptrvcid->getVcFrameCounterOctets(eExpedited),
                              lptrmapid->m_permapheaderLen,
                              lphyschanptr->m_Frame_Error_Control_Length); 
                              */
                            //
                            //
                            // leaving maxheaderless variable alone - new paradigm - max TFDF length = maxframelen - sechdr- sectrlr - iz - frame header (not counting frame counter bytes) - fecf - possibleOcfLen 
                            // this calc allows for either ABSENT ocf or NECESSARY(fxd)-OR-OPTIONAL(var) ocf
                            // length must be adjusted based on QoS Frame Counter octets such that total max tfdf len is m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR MINUS frame counter octets MINUMS tfdf hdr len
                            //
                            lptrmapid->m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR = 								 // length INCLUDING TFDF header
                                lptrvcid->m_vcid_Maximum_Transfer_Frame_Length     // VCID frame length (which may have been trumped by parent lengths)
                                - lptrvcid->m_LengthOfSpaceDataLinkSecurityHeader  // - MIB security header len
                                - lptrvcid->m_LengthOfSpaceDataLinkSecurityTrailer // - MIB security trailer len
                                - localIzLen                                       // - calculated insert zone length
                                - FRAME_PRIMARY_HEADER_OCTETS                      // - frame header len (if not truncated)
                                - lptrmapid->m_permapheaderLen                     // - not including TFDF header len
                                - lphyschanptr->m_Frame_Error_Control_Length       // - fecf length
                                - localOcfPossibleLen;													 	 // 4 if fixedlen&OCFrequired, 0 if fixedlen&ocfNOTrequired, 4 if variablelen& ocfallowed, 0 if variablelen & ocf NOT allowed

                            // klmprintf("m_vcid_Maximum_Transfer_Frame_Length %d\n", lptrvcid->m_vcid_Maximum_Transfer_Frame_Length);
                            // klmprintf("lptrvcid->m_LengthOfSpaceDataLinkSecurityHeader %d\n", lptrvcid->m_LengthOfSpaceDataLinkSecurityHeader);
                            // klmprintf("lptrvcid->m_LengthOfSpaceDataLinkSecurityTrailer %d\n", lptrvcid->m_LengthOfSpaceDataLinkSecurityTrailer);
                            // klmprintf("localIzLen %d\n", localIzLen);
                            // klmprintf("FRAME_PRIMARY_HEADER_OCTETS %d\n", FRAME_PRIMARY_HEADER_OCTETS);
                            // klmprintf("lptrmapid->m_permapheaderLen %d\n", lptrmapid->m_permapheaderLen);
                            // klmprintf("lphyschanptr->m_Frame_Error_Control_Length %d\n", lphyschanptr->m_Frame_Error_Control_Length);
                            // klmprintf("localOcfPossibleLen %d\n", localOcfPossibleLen);
                            // klmprintf("readMibConfig says %s m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR is %d and m_mapid_frameCounterOctets is %d\n",lptrmapid->mapktree(),lptrmapid->m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR, lptrmapid->m_mapid_frameCounterOctets);fflush(stdout);

                            // QUEUE ENTRIES ARE m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR **** PLUS ONE octet for QoS flag ****
                            // QUEUE ENTRIES ARE m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR **** PLUS ONE octet for QoS flag ****
                            // QUEUE ENTRIES ARE m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR **** PLUS ONE octet for QoS flag ****
                            // QUEUE ENTRIES ARE m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR **** PLUS ONE octet for QoS flag ****
                            // QUEUE ENTRIES ARE m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR **** PLUS ONE octet for QoS flag ****

                            // set all maps' var/fixed bools
                            if ( lptrmapid->m_map_ServiceDataUnitType == eMAP_PACKET ) // fixed packet   000
                            {
                                lptrmapid->m_ccsdsPacket = true;
                            }
                            else 
                            {
                                lptrmapid->m_ccsdsPacket = false; // false if either MAPA_SDU or OCTETSTREAM - make sure when you get an octet stream you don't call newKlmAddPacketSduTo_FIFO_Tx
                            }
                            //
                            // allocate two rx assembly buf(s) for each map (one for sequence controlled, one for expedited)
                            //
                            lptrmapid->m_RxAssemblyBuf[0] = new unsigned char [packetInfoMib.m_Maximum_Packet_Length + lphyschanptr->m_pc_Transfer_Frame_Length]; // for assembly of incoming parital packets rxd
                            lptrmapid->m_RxAssemblyBuf[1] = new unsigned char [packetInfoMib.m_Maximum_Packet_Length + lphyschanptr->m_pc_Transfer_Frame_Length]; // for assembly of incoming parital packets rxd
                            // propagate physchan OID info to vcid
                            lptrmapid->m_map_pcOidData = lphyschanptr->m_pcOIDdata; // propagate PC oid info
                        }	
                        lptrvcid->resetVcidOidTimer(); // resets every time-to-tx vcid timer and the physchan OID timer
                        //
                        // determine if there's only one mapid on this vcid (mapa_sdu loss flag only true if loss and there's ONLY ONE mapid on this vcid
                        //
                        if (lptrvcid->m_mapmap.size() == 1 ) // mapa_sdu loss flag only true if seq count anomaly AND there's ONLY ONE MAPID on this vcid. set convenient flag here
                        {
                            lptrvcid->m_oneMapidOnThisVcid = true; // one-check boolean to say there's only one mapid on this vcid
                        }
                        if ( lptrvcid->m_COP_in_Effect != noCopInEffect) // SOME cop is in effect
                        {
                            gvcid lgvcid;
                            lgvcid.set ( lphyschanptr->m_Name, lphyschanptr->m_Transfer_Frame_Version_Number, lptrMasterChannel->m_MC_SpacecraftId, lptrvcid->m_VCID);
                            //
                            // report CLCW rate to cop
                            // 
                            reportClcwRateToCop(lgvcid,lptrvcid->m_CLCW_Reporting_Rate);
                        }
                        //
                        //
                        // make sure there's a mapid0 default if there's not already one there
                        //
                        //
                        if ( lptrvcid->m_mapmap[0] == NULL ) // no map[0] already defined
                        {
                            lptrvcid->m_mapmap[0] = new kmapid(lphyschanptr, lptrMasterChannel->m_MC_ID, lptrvcid->m_VCID, 0 , lptrvcid ); // make one if it doesn't exist, replace it if it does
                            lptrvcid->m_mapmap[0]->m_map_Spacecraft_ID = lptrMasterChannel->m_MC_ID & 0xffff;  // assign spacecraft id from VIRTUAL_CHANNEL_MAP_IDs parameter
                            lptrvcid->m_vc_MAP_IDs[0] = true; // assign mapid0 as valid
                            // set default mapid 0 txbypass flag to expedited?
                        }
                    }	
                }	
            }	
        }

        bool insert_request ( unsigned char * isochInsertZoneData, String lphyschan ) // length specified by MIB value PHYSICAL_CHANNEL_Isochronous_Insert_Zone_Length
        {
            bool retval = false;
            if ( verifyPhysChan ( lphyschan ) )
            {
                pcmap[lphyschan]->putInsertZone(isochInsertZoneData);
                retval = true;
            }
            else
            {
                klmprintf("error - physical channel %s supplied to insert_request is not configured in managed parameters. ignored.\n",lphyschan.c_str());fflush(stdout);
                retval = false;
            }
            return retval;
        }
        bool mibPutFecf ( unsigned char * fecfData, String lphyschan ) // 2 or 4 octets. length specified by MIB value PHYSICAL_CHANNEL_Frame_Error_Control_Length
        {
            bool retval = false;
            if ( verifyPhysChan ( lphyschan ) )
            {
                pcmap[lphyschan]->putFecf(fecfData); // putFecf only copies PHYSICAL_CHANNEL_Frame_Error_Control_Length octets
                retval  = true;
            }
            return retval;
        }
        bool masterChannelFrameServiceRequest (  unsigned char * masterChannelFrameServiceData, gmasterChannelId MCid)
        {
            bool retval = false;
            String lphyschan = MCid.PHYSCHAN;
            //
            // only tx if 1) MCID matches mcid in frame 2) mcid is in managed parameters 3) mcid is configured to be a frame service mcid (can't mix)
            //
            int ltfvn = (masterChannelFrameServiceData[0] & 0xf0) >> 4;
            int lscid = (masterChannelFrameServiceData[0] & 0x0f);
            lscid <<= 8;
            lscid |= masterChannelFrameServiceData[1];
            lscid <<= 4;
            lscid |= (masterChannelFrameServiceData[2] & 0xf0) >> 4;
            int lagmcid = (65536 * ltfvn) + lscid;
            // klmprintf("mcfsrq- frame mc (%s/%d/%d) mcid mc (%s/%d/%d).\n",lphyschan.c_str(), ltfvn,lscid, MCid.PHYSCHAN.c_str(), MCid.TFVN,MCid.SCID);fflush(stdout);

            if ( ltfvn != MCid.TFVN || lscid != MCid.SCID ) // supplied mcid does not match mcid in frame
            {
                klmprintf("error - MCid (%d/%d) accompanying mc frame service frame does not match masterchannel in frame header (%d/%d). frame not sent.\n",ltfvn,lscid,MCid.TFVN,MCid.SCID);fflush(stdout);
                retval = false;
            }
            else if ( verify_MC_ID(MCid.PHYSCHAN,((MCid.TFVN * 65536) + MCid.SCID))) // IS in managed parameters - is it configured as mc frame service?
            {
                if ( pcmap[lphyschan]->m_MCmap[lagmcid]->m_mcFrameService ) // if this IS configured to be a frame service vcid in the managed parameters
                {
                    charint lkci;
                    lkci.i = 0;
                    lkci.c[0] = masterChannelFrameServiceData[5]; // lsb
                    lkci.c[1] = masterChannelFrameServiceData[4]; // msb
                    int lmasterChannelFrameServiceLen = lkci.i + 1; // since frame length in the frame is minus-1
                    String lphyschan = MCid.PHYSCHAN;
                    pcmap[lphyschan]->txFrame ( masterChannelFrameServiceData, lmasterChannelFrameServiceLen, 1 ); // transmit the frame // no repetitions as per 3/15/2018 4:42pm email
                    retval = true;
                }
                else
                {
                    klmprintf("error - supplied MCid (%s/%d/%d) not configured as masterchannel frame service in managed parameters. frame not sent.\n",MCid.PHYSCHAN.c_str(), MCid.TFVN,MCid.SCID);fflush(stdout);
                    retval = false;
                }
            }
            else // supplied mcid not in managed parameters
            {
                klmprintf("error - supplied MCid (%s/%d/%d) not in managed parameters. frame not sent.\n",MCid.PHYSCHAN.c_str(), MCid.TFVN,MCid.SCID);fflush(stdout);
                retval = false;
            }
            return retval;
        }
        /*
           bool masterChannelFrameServiceGet ( unsigned char * masterChannelFrameServiceData, int * masterChannelFrameServiceLen, masterchannelid_t mcid )
           {
           int lagmcid = ( mcid.TFVN * 65536 ) + mcid.SCID;
           bool goodretrieve = pcmap[mcid.PHYSCHAN]->m_MCmap[lagmcid]->getqMasterChannelFrameService ( masterChannelFrameServiceData,masterChannelFrameServiceLen );
           return goodretrieve;
           }
           */
        bool vcFrameServiceRequest ( unsigned char * vcFrameServiceData, gvcid_t gvcid )
        {
            bool retval = false;
            // it is assumed:
            // 	the receiver will have had the vcid set up to expect a vcid frame service frame
            //  the vcid is set up for a variable length frame upon configuration
            //
            String lphyschan = gvcid.PHYSCHAN;
            //
            // only tx if 1) GVCID matches gvcid in frame 2) vcid is in managed parameters 3) vcid is configured to be a frame service vcid (can't mix)
            //
            charint lkci;
            int ltfvn = (vcFrameServiceData[0] & 0xf0) >> 4;
            int lscid = (vcFrameServiceData[0] & 0x0f);
            lscid <<= 8;
            lscid |= vcFrameServiceData[1];
            lscid <<= 4;
            lscid |= (vcFrameServiceData[2] & 0xf0) >> 4;
            int lvcid = (vcFrameServiceData[3] & 0xe0) >> 5;
            lvcid |= (vcFrameServiceData[2] & 0x07) << 3;
            int lagmcid = (65536 * ltfvn) + lscid;
            if ( ltfvn != gvcid.TFVN || lscid != gvcid.SCID || lvcid != gvcid.VCID )
            {
                klmprintf("error - gvcid (%d/%d/%d) accompanying vc frame service frame does not match gvcid in frame header (%d/%d/%d). frame not sent.\n",ltfvn,lscid,lvcid,gvcid.TFVN,gvcid.SCID,gvcid.VCID);fflush(stdout);
                retval = false;
            }
            else if ( verifyVCID ( lphyschan, lagmcid , lvcid )) // GVCID is the same as the one in frame. verify that the GVCID is in the managed parameters
            {
                kphysicalChannel *lpcptr = pcmap[lphyschan]; // i use this a lot here

                if ( lpcptr->m_MCmap[lagmcid]->m_vcidmap[lvcid]->m_VcidFrameService ) // if this IS configured to be a frame service vcid in the managed parameters
                {
                    //
                    // get length from given frame
                    //
                    lkci.i = 0;
                    lkci.c[0] = vcFrameServiceData[5]; // lsb
                    lkci.c[1] = vcFrameServiceData[4]; // msb
                    int lvcFrameServiceLen = lkci.i + 1; // since frame length in the frame is minus-1
                    //
                    //
                    // copy in insert zone from THIS physical channel if it exists, starting at offset header+frame counter length and length PHYSICAL_CHANNEL_Isochronous_Insert_Zone_Length
                    //
                    //
                    if ( lpcptr->m_Presence_of_Isochronous_Insert_Zone == ePresent )
                    {
                        //
                        // frame counter len - is it an expedited or a sequence controlled frame?
                        //
                        int lframecounterlen;
                        unsigned char lizdata[MAX_IZ_LENGTH];
                        int lizlen;
                        if ( 0 == (vcFrameServiceData[6] & 0x80) ) // check the sequence control bit - if 0 it's sequence controlled, if 1 it's expedited
                        {
                            lframecounterlen = lpcptr->m_MCmap[lagmcid]->m_vcidmap[lvcid]->m_vcSeqCtrlCountOctets; // get frame counter length or sequence controlled frames
                        }
                        else // this is an expedited frame - use expedited frame counter length
                        {
                            lframecounterlen = lpcptr->m_MCmap[lagmcid]->m_vcidmap[lvcid]->m_vcExpIntCountOctets; // get frame counter length or expedited frames
                        }
                        lpcptr->getInsertZone(lizdata, &lizlen);
                        memcpy(&vcFrameServiceData[FRAME_HEADER_LENGTH + lframecounterlen],lizdata,lizlen);
                    }
                    pcmap[lphyschan]->txFrame ( vcFrameServiceData, lvcFrameServiceLen, 1 ); // transmit the frame - any repetitions?
                    retval = true;
                }
                else
                {
                    klmprintf("error - GVCID in supplied frame (%s/%d/%d/%d) not configured to be frame service VCID in managed parameters. frame not sent.\n",gvcid.PHYSCHAN.c_str(),gvcid.TFVN,gvcid.SCID,gvcid.VCID);fflush(stdout);
                    retval = false;
                }
            }
            else // supplied vcid not in managed parameters
            {
                klmprintf("error - supplied GVCID (%s/%d/%d/%d) not in managed parameters. frame not sent.\n",gvcid.PHYSCHAN.c_str(),gvcid.TFVN,gvcid.SCID,gvcid.VCID);fflush(stdout);
                retval = false;
            }
            // don't worry about counters or timers - this is a whole frame handed to us by the user
            return retval;
        }
        /*
           bool vcFrameServiceGet ( unsigned char * vcFrameServiceData, int * vcFrameServiceLen, gvcid_t gvcid )
           {
           String lphyschan = gvcid.PHYSCHAN;
           int lagmcid = ( gvcid.TFVN * 65536 ) + gvcid.SCID;
           int lvcid = gvcid.VCID;
           bool goodretrieve = pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->getqVcFrameService ( vcFrameServiceData,vcFrameServiceLen );
           return goodretrieve;
           }
           */
        bool ocfServiceRequest ( unsigned char * ocfRq, gvcid_t gvcid )
        {
            bool goodappend = false;
            String lphyschan = gvcid.PHYSCHAN;
            int lagmcid = ( gvcid.TFVN * 65536 ) + gvcid.SCID;
            int lvcid = gvcid.VCID;
            if ( verifyVCID(lphyschan, lagmcid, lvcid)) // if good vcid
            {
                // i decided on 2/27/2018 that i should allow ANY valid VCID to send an ocf up to its master channel. the include_OCF flag is still used by the receiver to deliver/notdeliver ocfs. 
                // if ( pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->m_vc_include_OCF == eTrue || pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[63]->m_vc_include_OCF == eTrue )
                //{
                goodappend = pcmap[lphyschan]->m_MCmap[lagmcid]->putMCidOcfBuf ( ocfRq, lvcid ); // put ocf buf using allowed-or-not-allowed flags from this vcid into is parent master channel
                //}
                //else
                //{
                //klmprintf("error ocfServiceRequest - ocf not allowed for physchan %s mcid %d vcid %d\n",lphyschan.c_str(),lagmcid, lvcid);fflush(stdout);
                //}
            }
            return goodappend;
        }
        bool putSecurityHeader ( unsigned char * secHdr, gvcid_t gvcid )
        {
            bool goodappend = false;
            String lphyschan = gvcid.PHYSCHAN;
            int lagmcid = ( gvcid.TFVN * 65536 ) + gvcid.SCID;
            int lvcid = gvcid.VCID;
            if ( verifyVCID(lphyschan, lagmcid, lvcid)) // if good vcid
            {
                if ( pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->m_PresenceOfSpaceDataLinkSecurityHeader == ePresent ) // must be present to put it
                {
                    pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->putVcidSecurityHeader ( secHdr ); // put secHdr 
                    klmprintf("putsechdr %s put to %s\n",secHdr,pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->vcktree());fflush(stdout);
                    goodappend = true;
                }
                else
                {
                    klmprintf("error putSecurityHeader - security header is set to ABSENT for physchan %s mcid %d vcid %d\n",lphyschan.c_str(),lagmcid, lvcid);fflush(stdout);
                }
            }
            return goodappend;
        }
        bool putSecurityTrailer ( unsigned char * secTrlr, gvcid_t gvcid )
        {
            bool goodappend = false;
            String lphyschan = gvcid.PHYSCHAN;
            int lagmcid = ( gvcid.TFVN * 65536 ) + gvcid.SCID;
            int lvcid = gvcid.VCID;
            if ( verifyVCID(lphyschan, lagmcid, lvcid)) // if good vcid
            {
                if ( pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->m_PresenceOfSpaceDataLinkSecurityTrailer == ePresent ) // must be present to put it
                {
                    pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->putVcidSecurityTrailer ( secTrlr ); // put secHdr 
                    klmprintf("putsectrailr %s put to %s\n",secTrlr,pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->vcktree());fflush(stdout);
                    goodappend = true;
                }
                else
                {
                    klmprintf("error putSecurityTrailer - security trailer is set to ABSENT for physchan %s mcid %d vcid %d\n",lphyschan.c_str(),lagmcid, lvcid);fflush(stdout);
                }
            }
            return goodappend;
        }
        bool map_MapaSDU_Request ( unsigned char * onlyDataNoHeader, /*20180522-RequestIsServiceThatIsSmartEnoughToGetLengthFromMAPA_SDU mapa_sdu length replaced oct30,2017 with managed mapid parameter m_map_mapaSduLength */ gmapid_t gmapid, int ltxSDU_ID, int sequenceControl0expedited1)
        {
            //
            //
            // 20180522 i learned that the mapa sdu SERVICE must be smart enough to glean the length information from the mapa itself. could be a structure or anything. 
            //          so i declare a mapa_sdu to be a character string whose length can be obtained by strlen(). that is the length that is passed to USLP.
            //
            //
            int lmapaSduGleanedFromSduItselfByService = strlen((char *)onlyDataNoHeader); // INCLUDES NULL
            bool goodappend = false;
            String lphyschan = gmapid.PHYSCHAN;
            int lagmcid = ( gmapid.TFVN * 65536 ) + gmapid.SCID;
            int lvcid = gmapid.VCID;
            int lmapid = gmapid.MAPID;
            if ( verifyMAP_ID ( lphyschan, lagmcid, lvcid, lmapid ) )
            {
                kmapid *lmapidPtr = pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->m_mapmap[lmapid];
                if ( lmapidPtr->m_map_ServiceDataUnitType != eMAPA_SDU )
                {
                    klmprintf("error - SDU Request called for map %s with non-mapaSdu frame type\n",lmapidPtr->mapktree());fflush(stdout);
                    lmapidPtr->mapasdu_notify_indication(gmapid, ltxSDU_ID, sequenceControl0expedited1, NOTIFY_IND_NEGATIVE_CONFIRM);
                }
                else
                {
                    // put the data directly into the available queue
                    klmprintf("mapaSDU_Request %s SDU_ID %d gtn %lld\n",lmapidPtr->mapktree(),ltxSDU_ID, globalUsTimeNow);fflush(stdout);
                    // goodappend = pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->m_mapmap[lmapid]->newKlmAddPacketSduTo_FIFO_Tx( onlyDataNoHeader, onlyDataNoHeaderLen, 0/*dummypvn*/ , sequenceControl0expedited1, true/* realtime*/);
                    goodappend = lmapidPtr->newKlmAddPacketSduTo_QUEUE_Tx( onlyDataNoHeader, lmapaSduGleanedFromSduItselfByService, 0/*dummypvn*/ , sequenceControl0expedited1, true/* realtime*/);
                    if ( goodappend )
                    {
                        lmapidPtr->mapasdu_notify_indication(gmapid, ltxSDU_ID, sequenceControl0expedited1, NOTIFY_IND_POSITIVE_CONFIRM);
                    }
                    else
                    {
                        lmapidPtr->mapasdu_notify_indication(gmapid, ltxSDU_ID, sequenceControl0expedited1, NOTIFY_IND_NEGATIVE_CONFIRM);
                    }
                }
            }
            return goodappend;
        }
        bool map_OctetStream_Request ( unsigned char * onlyDataNoHeader, /* int onlyDataNoHeaderLen replaced oct 30,2017 with managed mapid parameter m_map_octetStreamRequestLength*/ gmapid_t gmapid /* 2/21/2018 4:25pm greg kazz email removes this , int sequenceControl0expedited1*/)
        {
            bool goodappend = false;
            String lphyschan = gmapid.PHYSCHAN;
            int lagmcid = ( gmapid.TFVN * 65536 ) + gmapid.SCID;
            int lvcid = gmapid.VCID;
            int lmapid = gmapid.MAPID;
            if ( verifyMAP_ID ( lphyschan, lagmcid, lvcid, lmapid ) )
            {
                kmapid *lmapidPtr = pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->m_mapmap[lmapid];
                if ( lmapidPtr->m_map_ServiceDataUnitType != eOCTET_STREAM )
                {
                    klmprintf("error - OctetStream Request called for map %s with non-octetStream frame type\n",lmapidPtr->mapktree());fflush(stdout);
                }
                else
                {
                    kprMutex.lock();printf(" map_OctetStream_Request %s @%lld adding ",lmapidPtr->mapktree(),globalUsTimeNow),seedata(onlyDataNoHeader,lmapidPtr->m_map_octetStreamRequestLength); printf(" to pchan %s mc %d vcid %d lmapid %d \n", pcmap[lphyschan]->m_Name.c_str(), lagmcid, lvcid, lmapid);fflush(stdout);kprMutex.unlock();
                    // goodappend = pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->m_mapmap[lmapid]->newKlmAddOctetStreamToFifo( onlyDataNoHeader, onlyDataNoHeaderLen , sequenceControl0expedited1 );
                    goodappend = lmapidPtr->newKlmAddOctetStreamTo_QUEUE_Tx( onlyDataNoHeader, lmapidPtr->m_map_octetStreamRequestLength/*2/21/2018 4:25 greg kazz email removed this, sequenceControl0expedited1 */);
                }
            }
            return goodappend;
        }
        // real-time - no timer-dependent transmission - only fill/overflow transmission
        bool map_P_Request ( unsigned char * onlyDataNoHeader, int onlyDataNoHeaderLen, gmapid_t gmapid, int packetVersionNumber, int ltxSDU_ID, int sequenceControl0expedited1 )
        {
            bool retval = false;
            //
            // immediately reject packet if packet is bigger than max packet size managed parameter
            //
            if (onlyDataNoHeaderLen > packetInfoMib.m_Maximum_Packet_Length) // packets CAN be bigger than frame size because they can span frames
            {
                klmprintf("Packet request has length %d that exceeds managed parameter maximum packet size %d. Discarded.\n",onlyDataNoHeaderLen,packetInfoMib.m_Maximum_Packet_Length);fflush(stdout); // print error message and return false from request
            }
            else
            {
                String lphyschan = gmapid.PHYSCHAN;
                int lagmcid = ( gmapid.TFVN * 65536 ) + gmapid.SCID;
                int lvcid = gmapid.VCID;
                int lmapid = gmapid.MAPID;
                if ( verifyMAP_ID ( lphyschan, lagmcid, lvcid, lmapid ) )
                {
                    kmapid *lmapidPtr = pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->m_mapmap[lmapid];
                    if ( lmapidPtr->m_map_ServiceDataUnitType != eMAP_PACKET )
                    {
                        klmprintf("error - Packet Request called for map %s with non-packet frame type\n",lmapidPtr->mapktree());fflush(stdout);
                        lmapidPtr->mapp_notify_indication(gmapid, packetVersionNumber, ltxSDU_ID, sequenceControl0expedited1, NOTIFY_IND_NEGATIVE_CONFIRM);
                    }
                    else
                    {
                        klmprintf("\n\n rt_map_P_Request %s SDU_ID %d time %d adding len %d packet to pchan %s mc %d vcid %d lmapid %d pvn %d ", lmapidPtr->mapktree(), ltxSDU_ID, fromstartsecs(), onlyDataNoHeaderLen, pcmap[lphyschan]->m_Name.c_str(), lagmcid, lvcid, lmapid,packetVersionNumber);seeframe(onlyDataNoHeader,onlyDataNoHeaderLen);fflush(stdout);
                        // retval = pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->m_mapmap[lmapid]->newKlmAddPacketSduTo_FIFO_Tx ( onlyDataNoHeader, onlyDataNoHeaderLen, packetVersionNumber, sequenceControl0expedited1,  true /*realtime - not queued*/);
                        retval = lmapidPtr->newKlmAddPacketSduTo_QUEUE_Tx ( onlyDataNoHeader, onlyDataNoHeaderLen, packetVersionNumber, sequenceControl0expedited1,  true /*realtime - not queued*/);
                        if ( retval ) 
                        {
                            lmapidPtr->mapp_notify_indication(gmapid, packetVersionNumber, ltxSDU_ID, sequenceControl0expedited1,NOTIFY_IND_POSITIVE_CONFIRM);
                        }
                        else
                        {
                            lmapidPtr->mapp_notify_indication(gmapid, packetVersionNumber, ltxSDU_ID, sequenceControl0expedited1,NOTIFY_IND_NEGATIVE_CONFIRM);
                        }
                    }
                }
            }
            return retval;
        }
        int map_truncatedFrameRequest (unsigned char *rawData, gmapid GMAPID)
        {
            int retval = -1;
            String lphyschan = GMAPID.PHYSCHAN;
            int lagmcid = ( GMAPID.TFVN * 65536 ) + GMAPID.SCID;
            int lvcid = GMAPID.VCID;
            int lmapid = GMAPID.MAPID;
            // do a find to verify map exists
            // put the data directly into the available queue
            if ( verifyMAP_ID(lphyschan,lagmcid,lvcid,lmapid))
            {
                kmapid *lmapidPtr = pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->m_mapmap[lmapid]; // here just for debug
                klmprintf("\n rt_map_truncatedRq %s time %d\n", lmapidPtr->mapktree(), fromstartsecs());fflush(stdout);
                retval = pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->m_mapmap[lmapid]->mapBuildAndTxTruncatedFrame ( rawData, lagmcid, lvcid, lmapid); 
            }
            return retval;
        }
        void dingsem ( int sd )
        {
            sem_post ( &m_gotData_sem );
        }
        int getVcFrameServiceQueueSize ( gmapid_t gmapid )
        {
            String lphyschan = gmapid.PHYSCHAN;
            int lagmcid = ( gmapid.TFVN * 65536 ) + gmapid.SCID;
            int lvcid = gmapid.VCID; // don't need mapid
            return pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->getVcFrameQueueSize();
        }
        /*
           int getGmapQHeaderAndDataSize(gmapid_t gmapid)
           {
           String lphyschan = gmapid.PHYSCHAN;
           int lagmcid = (gmapid.TFVN * 65536) + gmapid.SCID;
           int lvcid = gmapid.VCID; // don't need mapid
           int lmapid = gmapid.MAPID;
           return pcmap[lphyschan]->m_MCmap[lagmcid]->m_vcidmap[lvcid]->m_mapmap[lmapid]->getMapqOutDataSize();
           }
           */

        void initScanIts ( void )
        {
            m_physchanit = pcmap.begin();
            m_mc_it = m_physchanit->second->m_MCmap.begin();
            m_vcidit = m_mc_it->second->m_vcidmap.begin();
            m_mapit = m_vcidit->second->m_mapmap.begin();
            m_pvn = packetInfoMib.m_minimumValidPvn; // start over at minimum pvn when you swap maps
            m_triedphyschans = 0;
            m_triedMCs = 0;
            m_triedvcids = 0;
            m_triedmaps = 0;
            m_triedpvns = 0;
        }
        void * run ( void * arg )
        {
            int *mibrunwhiletrue = (int *)arg; // allow external stoppage
#ifdef OLD_RUN_METHOD
            unsigned char headerAndDataToTx[MAX_FRAME_SIZE];
            int headerAndDataLen = MAX_FRAME_SIZE;
            unsigned char ocfData[MAX_OCF_LENGTH];
            int ocfLen = MAX_OCF_LENGTH;

            unsigned char izData[MAX_INSERT_ZONE_SIZE];
            int izLen = MAX_INSERT_ZONE_SIZE;

            /*
               int retrievesize;
               unsigned char McFsData[MAX_FRAME_SIZE];
               int McFsLen = MAX_FRAME_SIZE;

               unsigned char VCFsData[MAX_FRAME_SIZE];
               int VCFsLen = MAX_FRAME_SIZE;
               */

            struct timeval tv;

            kmapid *lptrmapid;
            kmasterChannel *lptrMCid;
            kvcid  *lptrvcid;
            kphysicalChannel *lptrphyschan;

            ocfLen = 0;
            izLen = 0;
            /*
               McFsLen = 0;
               VCFsLen = 0;
               */
            int minimumFutureTimeToSleepUntil = 0x7fffffff;
            long long ltimeUsToSleepUntilNextTx = 1;

            gettimeofday(&tv,NULL);
            startSecs = tv.tv_sec;
            sleep(1); // let main dump stuff
            while ( true )
            {
                gettimeofday(&tv,NULL);
                globalUsTimeNow = (long long)tv.tv_sec; // do multiplication separately so it's all done in long longs
                globalUsTimeNow *= 1000000ll;
                globalUsTimeNow += (long long)tv.tv_usec;
#ifdef DOPRINTFS
                klmprintf("whiletrue sleeping %d starting at %lld\n\n",ltimeUsToSleepUntilNextTx,globalUsTimeNow);fflush(stdout);
#endif // DOPRINTFS
                sem_timedwait ( &m_gotData_sem , &ts); // wait until we get data
                gettimeofday(&tv,NULL);
                globalUsTimeNow = tv.tv_sec;
#ifdef DOPRINTFS
                klmprintf("run ps sets gtn to %lld\n",globalUsTimeNow);fflush(stdout);
#endif // DOPRINTFS
                minimumFutureTimeToSleepUntil = 0x7fffffff;
#ifdef DOPRINTFS
                // 				klmprintf(". %d\n",globalUsTimeNow);fflush(stdout);
#endif // DOPRINTFS
                bool whatITxdWasQueueData = true; // as opposed to tx assemblybuf data

                ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                std::map <String,kphysicalChannel *>::iterator l_physchanit; // local iterators
                std::map <int, kmasterChannel *>::iterator l_mc_it;
                std::map <int, kvcid *>::iterator l_vcidit;
                std::map <int, kmapid *>::iterator l_mapit; // for scanning through map ids

                for ( l_physchanit = pcmap.begin(); l_physchanit != pcmap.end(); l_physchanit++ ) // always start from beginning
                {
                    lptrphyschan = l_physchanit->second;
                    lptrphyschan->getInsertZone(izData, &izLen);
                    for ( l_mc_it = l_physchanit->second->m_MCmap.begin(); l_mc_it != l_physchanit->second->m_MCmap.end(); l_mc_it++ ) // always start from beginning
                    {
                        lptrMCid = l_mc_it->second; // not really necessary
                        for ( l_vcidit = l_mc_it->second->m_vcidmap.begin(); l_vcidit != l_mc_it->second->m_vcidmap.end(); l_vcidit++ ) // always start from beginning
                        {
                            lptrvcid = l_vcidit->second;
                            for ( l_mapit = l_vcidit->second->m_mapmap.begin(); l_mapit != l_vcidit->second->m_mapmap.end(); l_mapit ++ ) // scan all maps
                            {
                                lptrmapid = l_mapit->second;
                                // debug
#ifdef DOPRINTFS
                                //								klmprintf("    examining gtn %d pc %s mc <%d> vc <%d> map <%d>\n",globalUsTimeNow, lptrphyschan->m_Name.c_str(),lptrMCid->m_MC_ID, lptrvcid->m_VCID, lptrmapid->m_map_MAPID);fflush(stdout);
#endif // DOPRINTFS
                                //
                                // cycle through all PVNs until done or until hit a txthisPvnNext situation (tx a pvn queue frame and endspan exists-but-not-time-to-tx-the-endspan-which-you-are-saving-in-case-another-packet-gets-added-to-the-endspan)
                                //
                                if ( lptrmapid->m_usTimeToTransmitStartedTfdf != FOREVER_IN_THE_FUTURE ) // some non-forever-off future time 
                                {
                                    if (lptrmapid->m_usTimeToTransmitStartedTfdf < minimumFutureTimeToSleepUntil )
                                    {
                                        // always check every mapid for minimum time to sleep
                                        minimumFutureTimeToSleepUntil = lptrmapid->m_usTimeToTransmitStartedTfdf;
                                    }
                                }
                                while ( lptrmapid->checkForMapData() )  // tx queues first, then time-to-tx map tx assembly bufs
                                {
                                    int localIZlen = izLen;
                                    // handle IZ on vcid level - no IZ if vcid frame type is variable or if physchan is false
                                    if ( lptrphyschan->m_Presence_of_Isochronous_Insert_Zone == eFalse || lptrvcid->m_vcid_Transfer_Frame_Type == eVariable )
                                    {
                                        localIZlen = 0; // NO INSERT ZONE in this case
                                    }
                                    // check for retval from getPacketToTx - may return that there's no data
                                    lptrmapid->getPacketToTx(headerAndDataToTx, &headerAndDataLen, &whatITxdWasQueueData); // gets queued data or leftover tx-assembly-buf data if out of queued data and it's time to tx
                                    kprMutex.lock();printf("getPkthdrdatalen = %d data ",headerAndDataLen);seedata(headerAndDataToTx, headerAndDataLen);printf("\n");fflush(stdout);kprMutex.unlock();
                                    klm random text to see if this is in scope lptrphyschan->uslptx.putEverythingButDatafieldHeaderAndData
                                        (
                                         lptrphyschan->m_Transfer_Frame_Version_Number,   // version_id - same on all physchans - table 5-2, note 1 4/26/2016 spec
                                         lptrmapid->m_map_Spacecraft_ID,    // scid,
                                         lptrvcid->m_source0Destination1,   // dest_src, 0=scid is SOURCE of frame, 1=scid is DEST of the frame based on whether VCID's MCID's spacecraftId = global_MY_SPACECRAFT_ID
                                         lptrvcid->m_VCID,    // vcid,
                                         lptrmapid->m_map_MAPID,   // mapid,
                                         0,   // eohdr,
                                         lptrmapid->m_txBypassFlag,   // bypassFlag ,
                                         lptrmapid->m_protocolCommandControlFlag, // command control flag that is as independnet as it can be. on the map level . this should have been obtained from the prox-1 frame. 
                                         0,   // reserveSpares,
                                         ocfLen,    // ocfLen,
                                         ocfData,   // *ocfData,
                                         lptrvcid->getVcFrameCounterOctets(lptrmapid->m_txBypassFlag),   // vcFrameCountOctets,
                                         lptrvcid->getVcFrameCounterAndInc(lptrmapid->m_txBypassFlag),   // vcFrameCounter,
                                         localIZlen,    // insert zone len (may have been trumped to 0 by frame type)
                                         izData,   // *insert zone data
                                         lptrvcid->m_LengthOfSpaceDataLinkSecurityHeader,   // secHdrLen,
                                         lptrvcid->m_spaceDataLinkSecurityHeader, // *secHdrData,
                                         lptrvcid->m_LengthOfSpaceDataLinkSecurityTrailer,                    // secTrlrLen,
                                         lptrvcid->m_spaceDataLinkSecurityTrailer, // *secTrlrData,
                                         lptrphyschan->m_Frame_Error_Control_Length,  // fecfLen,
                                         lptrphyschan->m_fecfData // *fecfData
                                             );
                                    lptrphyschan->uslptx.putDatafieldHeaderAndData ( headerAndDataToTx, headerAndDataLen ); // TFDF LEN (this means the same build_frame can be used for fixed or variable length frames)
                                    lptrphyschan->uslptx.buildFrame(); // build an UNtruncated frame
                                    // have the physical channel transmit the frame
                                    klmprintf("      TRANSMIT from RUN() v/m %d/%d at %lld mapdataframe framelen %d \n",lptrvcid->m_VCID,lptrmapid->m_map_MAPID,globalUsTimeNow, lptrphyschan->uslptx.getTotalFrameLen());fflush(stdout);
                                    int lreps;
                                    if ( ltxBypassFlag == eSequenceControlled )
                                    {
                                        lreps = m_myVcidParent->m_Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_service_data_on_the_Sequence_Controlled_Service; // limited by physchan reps value
                                    }
                                    else
                                    {
                                        lreps = m_myVcidParent->m_RepetitionsValueUNLIMITEDbyPhyschanValue; // unlimited by physchan reps value for expedited frames
                                    }
                                    lptrphyschan->txFrame ( lptrphyschan->uslptx.getframe(),lptrphyschan->uslptx.getTotalFrameLen(), lreps );
                                    // extend when to tx next timeout vcid frame
                                    lptrvcid->resetVcidOidTimer(); // txed on this vcid; reset its timeout and the OID timeout
                                    //
                                    // if what i just transmitted was queue data and there is an endspan
                                    //
                                    /****??????????
                                      if ( ! whatITxdWasQueueData )
                                      {
                                      lptrmapid->m_txBufStartsWithContinuation = false; // this pvn does NOT have an endspan
                                      }
                                      ????????*******/
                                }
                                klmprintf("  v/m %d/%d minimumFutureTimeToSleepUntil = %d\n",lptrvcid->m_VCID,lptrmapid->m_map_MAPID,minimumFutureTimeToSleepUntil );fflush(stdout);
                                // klmprintf(" v/m %d/%d ttempty %d gt %d diff %d\n", lptrvcid->m_VCID,lptrmapid->m_map_MAPID, lptrmapid->m_usTimeToTransmitStartedTfdf , globalUsTimeNow , (lptrmapid->m_usTimeToTransmitStartedTfdf - globalUsTimeNow) );fflush(stdout); // some nonzero future time 
                            }
                            // check vcid for frame service (this may reset vcid tx clock, so do this before checking vcid tx clock)
#ifdef DOPRINTFS
                            // klmprintf("    examining VCID %d tttx %d\n", lptrvcid->m_VCID,lptrvcid->m_vcidUsTimeToTxMinTimeBetweenVcidFrames );fflush(stdout);
#endif // DOPRINTFS
                            /*april 2017 - moved frame service to be event-driven instead of "timer driven and queued"
                              if ( lptrvcid->getqVcFrameService ( headerAndDataToTx, &headerAndDataLen))
                              {
                              kprMutex.lock();printf("					txing VC %d FRAME SERVICE ",lptrvcid->m_VCID); seedata(headerAndDataToTx,headerAndDataLen); printf("\n");fflush(stdout);kprMutex.unlock();
                              lptrphyschan->txFrame(headerAndDataToTx,headerAndDataLen);
                              lptrvcid->resetVcidOidTimer();
                              } 
                              */
                            // always check every vcid for minimum time to sleep
                            klmprintf("  v %d before minimumFutureTimeToSleepUntil = %d\n",lptrvcid->m_VCID,minimumFutureTimeToSleepUntil );fflush(stdout);
                            if ( lptrvcid->m_vcidUsTimeToTxMinTimeBetweenVcidFrames < minimumFutureTimeToSleepUntil )
                            {
                                minimumFutureTimeToSleepUntil = lptrvcid->m_vcidUsTimeToTxMinTimeBetweenVcidFrames;
                            }
                            klmprintf("  v %d after minimumFutureTimeToSleepUntil = %d\n",lptrvcid->m_VCID,minimumFutureTimeToSleepUntil );fflush(stdout);
                        }
                        //
                        // check vcid for frame service (this may reset vcid tx clock, so do this before checking vcid tx clock)
                        //
                        /*april 2017 - moved frame service to be event-driven instead of "timer driven and queued"

                          if ( lptrMCid->getqMasterChannelFrameService ( headerAndDataToTx, &headerAndDataLen))
                          {
                          kprMutex.lock();printf("					txing MC %d FRAME SERVICE ",lptrMCid->m_MC_ID); seedata(headerAndDataToTx,headerAndDataLen); printf("\n");fflush(stdout);kprMutex.unlock();
                        // no mc timer to reset
                        lptrphyschan->txFrame(headerAndDataToTx,headerAndDataLen);
                        } 
                        */
                    }
                }
                ltimeUsToSleepUntilNextTx = minimumUsFutureTimeToSleepUntil - globalUsTimeNow;
                if ( ltimeUsToSleepUntilNextTx < 1 ) // if time is less than minimum, sleep minimum
                {
                    ltimeUsToSleepUntilNextTx = 1; // guarantee positive sleep
                }
            }
#endif // OLD_RUN_METHOD
#ifdef TIMER_TIMEOUT_STUFF
            //
            //
            //
            // new run method - ONLY used as a timer to do all the automatic stuff
            //
            //
            unsigned char ltfdf[MAX_FRAME_SIZE];
            int ltfdfLen;
            // unsigned char ltfdf[MAX_FRAME_SIZE]; // for retrieving tfdf from queue
            long long theSoonestUsTimerExpiration; // soonest timer expiration on the vcid
            //
            kmasterChannel *lptrMCid;
            kvcid  *lptrvcid;
            kphysicalChannel *lptrphyschan;
            struct timeval tv;
            gettimeofday(&tv,NULL);
            startSecs = tv.tv_sec;
            klmprintf("startsecs = %d\n",startSecs);fflush(stdout);
            long long lminWaitUntil;
            while ( *mibrunwhiletrue )
            {
                // get absolute microseconds now
                gettimeofday(&tv,NULL);
                globalUsTimeNow = (long long)tv.tv_sec - startSecs; // do multiplication separately so it's all done in long longs
                // globalUsTimeNow *= 1000000ll;
                // globalUsTimeNow += (long long)tv.tv_usec;
                // now scan everybody to see what to do
                std::map <String,kphysicalChannel *>::iterator l_physchanit; // local iterators
                std::map <int, kmasterChannel *>::iterator l_mc_it;
                std::map <int, kvcid *>::iterator l_vcidit;
                std::map <int, kmapid *>::iterator l_mapit; // for scanning through map ids

                lminWaitUntil = FOREVER_IN_THE_FUTURE; // minimum wait for all physical channels
                for ( l_physchanit = pcmap.begin(); l_physchanit != pcmap.end(); l_physchanit++ ) // always start from beginning
                {
                    lptrphyschan = l_physchanit->second;
                    for ( l_mc_it = l_physchanit->second->m_MCmap.begin(); l_mc_it != l_physchanit->second->m_MCmap.end(); l_mc_it++ ) // always start from beginning
                    {
                        lptrMCid = l_mc_it->second; // not really necessary
                        //
                        //
                        // go through twice - once for expedited frames, once for sequence controlled frames
                        //
                        //
                        for ( int kzxmxq = 0 ; kzxmxq < 2 ; kzxmxq ++ )
                        {
                            int seqCtrl0orExp1;
                            switch(kzxmxq)
                            {
                                case 0: seqCtrl0orExp1 = eSequenceControlled;
                                        break;
                                case 1: seqCtrl0orExp1 = eExpedited;
                                        break;
                            }

                            for ( l_vcidit = l_mc_it->second->m_vcidmap.begin(); l_vcidit != l_mc_it->second->m_vcidmap.end(); l_vcidit++ ) // always start from beginning
                            {
                                lptrvcid = l_vcidit->second;
                                if ( lptrvcid->m_VCID != 63 )
                                {

                                    //
                                    // if it's time to do something, do it and reset the timer
                                    //
                                    // things to do are: a) send a ready-to-send-TFDF from a queue b) send-a-started-but-unfinished-TFDF and c) send SOME frame on the vcid for max-time-between-frames-of-the-same-vcid
                                    //
                                    for ( l_mapit = lptrvcid->m_mapmap.begin(); l_mapit != lptrvcid->m_mapmap.end(); l_mapit++ )
                                    {
                                        //
                                        // a) see if there are any ready-to-send-TFDFs in any queue
                                        //
                                        kmapid *mp = l_mapit->second;
                                        if ( seqCtrl0orExp1 == eSequenceControlled )
                                        {
                                            mp->m_qSeqCtrlTfdfs_mutex.lock();
                                        }
                                        else
                                        {
                                            mp->m_qExpeditedTfdfs_mutex.lock();

                                        }
#define FIVE_SECOND_FRAMES 1
                                        bool txdQframe = false;
                                        if ( seqCtrl0orExp1 == eSequenceControlled ) // SEQCTRL QUEUE
                                        {
#ifdef FIVE_SECOND_FRAMES
                                            if ( mp->m_qSeqCtrlTfdfs->get_packet_count() > 0 ) // something to tx
#else  // FIVE_SECOND_FRAMES
                                                while ( mp->m_qSeqCtrlTfdfs->get_packet_count() > 0 ) // something to tx
#endif // FIVE_SECOND_FRAMES
                                                {
                                                    ltfdfLen = mp->m_qSeqCtrlTfdfs->retrieve ( ltfdf, 0  ); // give it a length you want   2nd parameter is unused in CircularPacketQueue::retrieve(1,2)
                                                    txdQframe = true;
                                                    mp->TXfromQueue( eSequenceControlled, ltfdf, ltfdfLen , "mainrun") ;
                                                }
                                            //klmq klmprintf("										tx @%lld all SeqCtrl map %d tfdfs end \n",globalUsTimeNow, l_mapit->second->m_map_MAPID);fflush(stdout);
                                        }
                                        else // EXP queue
                                        {
#ifdef FIVE_SECOND_FRAMES
                                            if ( mp->m_qExpeditedTfdfs->get_packet_count() > 0 ) // something to tx
#else  // FIVE_SECOND_FRAMES
                                                while ( mp->m_qExpeditedTfdfs->get_packet_count() > 0 ) // something to tx
#endif // FIVE_SECOND_FRAMES
                                                {
                                                    ltfdfLen = mp->m_qExpeditedTfdfs->retrieve ( ltfdf, 0  ); // give it a length you want   2nd parameter is unused in CircularPacketQueue::retrieve(1,2)
                                                    txdQframe = true;
                                                    mp->TXfromQueue( eExpedited, ltfdf, ltfdfLen , "mainrun") ;
                                                }
                                            //klmqklmprintf("										tx @%lld all Expedit map %d tfdfs end \n",globalUsTimeNow, l_mapit->second->m_map_MAPID);fflush(stdout);
                                        }
                                        //
                                        // b) send-a-started-but-unfinished-TFDF 
                                        //
#ifdef FIVE_SECOND_FRAMES
                                        if ( !txdQframe && globalUsTimeNow >= mp->m_usTimeToTransmitStartedTfdf ) // if it's time to tx a started-unfinished tfdf 
#else // FIVE_SECOND_FRAMES
                                            if ( globalUsTimeNow >= mp->m_usTimeToTransmitStartedTfdf ) // if it's time to tx a started-unfinished tfdf 
#endif // FIVE_SECOND_FRAMES
                                            {
                                                // tx it if there's something there and reset the fill-tx-buf variables
                                                mp->mapTxStartedTfdfTimerExpired();
                                                if (txdQframe) // dummy use to toggle between five second delay per frames and empty-the-queue-every-time-you-can
                                                {
                                                    klmprintf("d");fflush(stdout); // dummy use to toggle between five second delay per frames and empty-the-queue-every-time-you-can
                                                }
                                            }
                                        if ( seqCtrl0orExp1 == eSequenceControlled )
                                        {
                                            mp->m_qSeqCtrlTfdfs_mutex.unlock();
                                        }
                                        else
                                        {
                                            mp->m_qExpeditedTfdfs_mutex.unlock();
                                        }
                                    }
                                    //
                                    // c) send SOME frame on the vcid for max-time-between-frames-of-the-same-vcid
                                    // m_vcidUsTimeToTxMinTimeBetweenVcidFrames should always stay FOREVER_IN_THE_FUTURE if physical channel frame type is not FIXED
                                    //
                                    if ( lptrvcid->m_vcidUsTimeToTxMinTimeBetweenVcidFrames <= globalUsTimeNow ) // vcid timer expired
                                    {
                                        kvcid *lOIDptr = lptrMCid->m_vcidmap[63]; // get a pointer at this MC's corresponding OID vcid (won't get here from mc/vc frame service frames becuasse their timers aren't checked)
                                        // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID framesunsigned char locfData[MAX_OCF_LENGTH];
                                        // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frames
                                        // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frames int locfDataLen;
                                        // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frames lOIDptr->getVcidOcfBuf(locfData,&locfDataLen); // mutex-get ocf buf
                                        // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frameslptrphyschan->txOIDframe(locfData,locfDataLen,lptrMCid->m_MC_ID,lOIDptr->getVcFrameCounterOctets(eExpedited), lOIDptr->getVcFrameCounterAndInc(eExpedited)); // tx the idle frame specified in 4.1.4.1.6 
                                        lptrphyschan->txOIDframe(lptrMCid->m_MC_ID,lOIDptr->getVcFrameCounterOctets(eExpedited), lOIDptr->getVcFrameCounterAndInc(eExpedited)); // tx the idle frame specified in 4.1.4.1.6 
                                        // klm918 decrementedUponGet() lptrvcid->decrementMCidOcfDeliveryCount(); // decrement the delivery count of the OCF since you may have just delivered it
                                        //
                                        // ALWAYS bump the vcOidTimeToTx timer of the vcid whose oid timer expired out by the release time 
                                        //
                                        if ( lptrvcid->m_timedVcidReleasesFlag )
                                        {
                                            // lvcidptr->m_vcidUsTimeToTxMinTimeBetweenVcidFrames = globalUsTimeNow + (lvcidptr->m_Maximum_delay_in_milliseconds_between_releases_of_frames_of_the_same_VC * 1000); // dealing in microseconds
                                            lptrvcid->m_vcidUsTimeToTxMinTimeBetweenVcidFrames = globalUsTimeNow + (lptrvcid->m_Maximum_delay_in_milliseconds_between_releases_of_frames_of_the_same_VC); // dealing in microseconds
                                        }
                                    }
                                    // after you may have transmitted, now find the minimum time to sleep after you've done everything that there is to do
                                    //
                                    theSoonestUsTimerExpiration = lptrvcid->getSoonestTimerExpiration(); // find the soonest time to do something on this vcid
                                    if ( theSoonestUsTimerExpiration < lminWaitUntil ) // smaller minimum wait
                                    {
                                        lminWaitUntil = theSoonestUsTimerExpiration;
                                    }
                                }
                            }
                        }
                    }
                }
#ifdef FIVE_SECOND_FRAMES
                // sleep(1);
#else  // FIVE_SECOND_FRAMES
                if ( lminWaitUntil != FOREVER_IN_THE_FUTURE ) // if there WAS a time to sleep until
                {
                    long long gap = lminWaitUntil - globalUsTimeNow;

                    // int secsleep = (int)(gap/1000000ll);
                    int secsleep = (int)gap;
                    klmprintf("sleeping %d gap %lld\n",secsleep,gap);fflush(stdout);
                    sleep(secsleep < 1?1:secsleep);  // number of seconds to sleep
                }
                else // otherwise sleep the minimum MP milliseconds-until
                {
                    klmprintf("default sleeping 1\n");fflush(stdout);
                    sleep(1);
                }
#endif // FIVE_SECOND_FRAMES
            }
#endif // TIMER_TIMEOUT_STUFF
            klmprintf("mib run exiting\n");fflush(stdout);
            return NULL;
        }
        void dumpGmapid ( void )
        {
            klmprintf ( "checking pc %s:mc %2d:vc %2d:mapid %2d pvn %2d ", m_physchanit->second->m_Name.c_str() ,m_mc_it->second->m_MC_ID, m_vcidit->second->m_VCID, m_mapit->second->m_map_MAPID, m_pvn);
            fflush ( stdout );
        }
        int rx(void  ) // int rx - the function to call to sit here and listen for mib stuff
        {
            unsigned char rxbuf[MAX_FRAME_SIZE];
            int rxframelen = 0;
            initScanIts(); // point all iterators at first item of everything
#ifdef IP_RECEIVE
            const char * m_interface = "ALL_INTERFACES"; // hardcode for now
#endif // IP_RECEIVE
#ifdef FILE_RECEIVE
#ifdef ASCII_FILE_RECEIVE
            FILE *fprx = fopen(klmReadFromThisFile,"r"); // read ASCII with fgets
            if ( fprx == NULL )
            {
                klmprintf("could not open file %s for reading. exiting.\n",klmReadFromThisFile);fflush(stdout);exit(1);
            }
#endif // ASCII_FILE_RECEIVE
#ifdef BINARY_FILE_RECEIVE
            FILE *fprx = fopen(klmReadFromThisFile,"rb"); // read BINARY with fread()
            if ( fprx == NULL )
            {
                klmprintf("could not open file %s for reading. exiting.\n",klmReadFromThisFile);fflush(stdout);exit(1);
            }
#endif// BINARY_FILE_RECEIVE
#endif // FILE_RECEIVE


            // receive
            kphysicalChannel *lphyschanptr;
#ifdef IP_RECEIVE
            for ( m_physchanit = pcmap.begin(); m_physchanit != pcmap.end(); m_physchanit++ )
            {
                lphyschanptr = m_physchanit->second;
                if ( ! lphyschanptr->m_RXsock.open ( lphyschanptr->m_rxport, lphyschanptr->m_multicast_addr ) ) // klmdebug
                {
                    fprintf ( stderr, "main:  open ( port=%d, multicast=%s, interface=%s ) ERROR -- %s\n",
                            lphyschanptr->m_rxport, lphyschanptr->m_multicast_addr,
                            ( m_interface  ?  m_interface : "none" ), lphyschanptr->m_RXsock.get_syserrstr() );
                    fflush ( stderr );
                    return 1;
                }
                else
                {
                    klmprintf ( "physchan %s listening on ipaddr %s port <%d>\n",lphyschanptr->m_Name.c_str(), lphyschanptr->m_multicast_addr,lphyschanptr->m_rxport ); fflush ( stdout );
                }
            }
#endif // IP_RECEIVE
            initScanIts(); // point all iterators at first item of everything
            while ( true )
            {
#ifdef IP_RECEIVE
                // bump to next physical channel ONLY if ip receive - on file receive everything is on ONE physchan
                if ( ++m_physchanit == pcmap.end() )
                {
                    m_physchanit = pcmap.begin();
                }
#endif // IP_RECEIVE
                lphyschanptr = m_physchanit->second;
#ifdef IP_RECEIVE
                if ( ! lphyschanptr->m_RXsock.query(0,0)) //  if there's no frame
                {
                    continue;
                }
#endif // IP_RECEIVE
#ifdef FILE_RECEIVE
#ifdef ASCII_FILE_RECEIVE
                bool foundGotAFrameLine = false;
                char *fromcp;
                /*
                // if file is screencap from ur output:
                while(!foundGotAFrameLine)
                {
                fromcp = fgets((char *)rxbuf,MAX_FRAME_SIZE,fprx);
                if ( fromcp == NULL )
                {
                klmprintf("end of file reached for file %s. exiting.\n",klmReadFromThisFile);fflush(stdout);exit(1);
                }
                int lrb = strlen((char *)rxbuf);
                rxbuf[lrb-1] = '\0'; // null out newline
                lrb--; // account for nulling out newline
                if ( strstr((char *)rxbuf,"got a frame") != NULL )
                {
                foundGotAFrameLine = true;
                fromcp = strchr((char *)rxbuf,':');
                fromcp++; // point past first space after :
                }
                }
                */
                // if file is seedata dump of ONLY incoming data
                // i.e. of the format 
                // #comment
                // c0 02 a0 00 00 13 02 00 01 03 00 04  R  L  D  7 e1 04  E  N
                // #comment
                // c0 02 a0 00 00 13 02 00 02 03 00 04  R  L  D  7 e1 04  E  N
                // #comment
                // c0 02 a0 00 00 13 02 00 03 03 00 04  R  L  D  7 e1 04  E  N

                while(!foundGotAFrameLine)
                {
                    fromcp = fgets((char *)rxbuf,MAX_FRAME_SIZE,fprx);
                    if ( fromcp == NULL )
                    {
                        klmprintf("end of file reached for file %s. exiting.\n",klmReadFromThisFile);fflush(stdout);exit(1);
                    }
                    int lrb = strlen((char *)rxbuf);
                    rxbuf[lrb-1] = '\0'; // null out newline
                    lrb--; // account for nulling out newline
                    if ( rxbuf[0] != '#')
                    {
                        foundGotAFrameLine = true;
                        fromcp = (char *)&rxbuf[0];
                    }
                }
                klmprintf("filerxd frmln      <%s>\n",fromcp);fflush(stdout);
                rxframelen = 0;
                char convertbuf[4];
                int convertbufIndex;
                while( *fromcp != '\0' ) // not pointing at character
                {
                    while (*fromcp == ' ') fromcp++;
                    if ( *fromcp == '\0' ) 
                    {
                        break;
                    }
                    else if (*fromcp != ' ') // nonspace
                    {
                        convertbufIndex = 0;
                        convertbuf[convertbufIndex++] = *fromcp++; // at least one character
                        if ( *fromcp == ' ' ||*fromcp == '\0' ) 
                        {
                            // do one-char conversion on convertbuf
                            rxbuf[rxframelen++] = convertbuf[0];
                        }
                        else  // 2 char convert
                        {
                            int hexval = 0;
                            convertbuf[convertbufIndex++] = *fromcp++; // at least one character
                            // now have 2 chars
                            // do first char
                            if ( isdigit(convertbuf[0]) ) 
                            {
                                hexval = (convertbuf[0] - 48) * 16; // 48-57 converted to 0-9 then leftshifted
                            }
                            else // is a-c
                            {
                                hexval = (convertbuf[0] - 87) * 16; // 97-102 converted to 10-15 then leftshifted
                            }
                            if ( isdigit(convertbuf[1]) ) 
                            {
                                hexval += convertbuf[1] - 48; // 48-57 converted to 0-9 then leftshifted
                            }
                            else // is a-c
                            {
                                hexval += convertbuf[1] - 87; // 97-102 converted to 10-15 then leftshifted
                            }
                            rxbuf[rxframelen++] = hexval;	
                        }
                    }
                }
#endif// ASCII_FILE_RECEIVE
#ifdef BINARY_FILE_RECEIVE
                rxframelen = MAX_FRAME_SIZE;
                size_t kfzcpq = fread(rxbuf,rxframelen,1,fprx);
                if (kfzcpq == 0) exit(2);

#endif // BINARY_FILE_RECEIVE

#endif // FILE_RECEIVE

#ifdef IP_RECEIVE
                // get a frame
                rxframelen = lphyschanptr->m_RXsock.read ( rxbuf, (int)sizeof ( rxbuf ) );
                // check for socket errors
                if ( rxframelen < 1 )
                {
                    fprintf ( stderr, "main:  socket read error, rxframelen=%d -- %s\n", rxframelen, lphyschanptr->m_RXsock.get_syserrstr() );
                    fflush ( stderr );
                    continue;
                }

#endif //  IP_RECEIVE

                if ( m_mibGIVEWHOLEFRAMEFN != NULL )
                {
                    m_mibGIVEWHOLEFRAMEFN(rxbuf,rxframelen); // give the whole frame to the rxfn
                }

                // get the uslp frame components
                kprMutex.lock();printf ( "got a frame len %02d: ",rxframelen ); seeframe ( rxbuf,rxframelen ); printf ( "\n" ); fflush ( stdout );kprMutex.unlock();
                //
                //
                // KLUGE for 
                //
                //
                //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// fastbit
#ifdef PTFBITFIELDREWRITTEN
                int ptfLfirstOctetPastVcCounters; 
                bool ptfIsTruncatedFrame = false;  // flag
                bool ptfIsOidFrame = false; // flag
                bool ptfLgoodFrame = parseTransferFrameHeader( // VERIFIES VALID MCID, VCID, MAPID
                        lphyschanptr, 
                        rxbuf, // pointer at octet 0 of the frame
                        rxframelen, 
                        &ptfVersion_id,
                        &ptfSpacecraftId,
                        &ptfDest_src,
                        &ptfVcid,
                        &ptfMapid,
                        &ptfEndOfTransferFrameHeader,
                        &ptfFramelen,
                        &ptfBypassFlag,
                        &ptfProtocolCommandControlFlag,
                        &ptfOcfFlag,
                        &ptfVcSeqCounterOctets,
                        &ptfVcSequenceCount, // actual sequence count (can't be more octets than vcSeqCounterOctets)
                        &ptfLfirstOctetPastVcCounters,
                        &ptfIsTruncatedFrame,  // flag
                        &ptfIsOidFrame // flag
                        );

                m_vcFrameCountOctets = ptfVcSeqCounterOctets;
                int lptfMasterchan = (ptfVersion_id * 65536) + ptfSpacecraftId;
                if ( ptfLgoodFrame ) // if good frame (and good means mcid,vcid,mapid have been verified) and can also mean it's a truncated frame
                {
                    int lptfVcid = ptfVcid; // depending on the setting in the VCID
                    int lptfMapid = ptfMapid;

                    kmasterChannel *lptfMasterchanptr = lphyschanptr->m_MCmap[lptfMasterchan];
                    kvcid *lptfVcidptr = lptfMasterchanptr->m_vcidmap[lptfVcid];
                    kmapid *lptfMapidptr = lptfVcidptr->m_mapmap[lptfMapid];
                    //
                    // handle possible FARM action (request go-back-two if missed frame)
                    //
                    if ( lptfVcidptr->m_farmfn != NULL ) // if this is a farm function 
                    {
                        if ( ! lptfVcidptr->m_farmfn(ptfVcSequenceCount)) // feed it the sequence count and let IT trigger a retransmit in the tx thread if need be
                        {
                            continue; // SKIP this frame if it's determined to have a bad sequence counter value
                        }
                    }
                    // first handle truncated frame
                    if ( ptfIsTruncatedFrame ) 
                    {
                        // transfer frame header is 4 bytes, transfer frame data field header is 1 byte
                        // masterchan, vcid, mapid already verified in parse-TransferFrameHeader
                        ptfProtocolId = 777; // klmAreYouSure - why have protocol ID in deliverRawDataFromTruncatedFrame()?
                        klmprintf ( "ptf truncated %d-octet protId %d data to physchan %s MC %d vcid %d mapid %d\n",rxframelen - 4, ptfProtocolId, lphyschanptr->m_Name.c_str(), lptfMasterchan,lptfVcid,lptfMapid ); fflush ( stdout );
                        // lphyschanptr->m_MCmap[lptfMasterchan]->m_vcidmap[lptfVcid]->m_mapmap[lptfMapid]->deliverRawDataFromTruncatedFrame(lphyschanptr->m_Name, lptfMasterchan, ptfProtocolId, &rxbuf[4] ); // deliver protId & data
                        lptfMapidptr->deliverRawDataFromTruncatedFrame(lphyschanptr->m_Name, lptfMasterchan, &rxbuf[4] ); // deliver data (NO protocol id)
                    }
                    //
                    // handle TFDF datafield-and-heade/ good frame with good security if it has security - deliver fields (iz, ocf, tfdf)
                    //
                    else if ( lptfMasterchanptr->m_mcFrameService ) // if this is a mcFrameService mcid
                    {
                        // deliver entire frame to mc frame service on this mcid
                        lptfMasterchanptr->deliverMcFrameServiceFrame ( lphyschanptr->m_Name, rxbuf,rxframelen );
                    } 
                    else if ( lptfVcidptr->m_VcidFrameService ) // this is a vcid frame service vcid
                    {
                        lptfVcidptr->deliverVcidFrameServiceFrame ( lphyschanptr->m_Name, lptfMasterchan, rxbuf,rxframelen );
                    }
                    else // normal frame AND OID frame (with a few exceptions for oid frame)
                    {
                        // tfdf len = TotalFrameLen - FrameHdrLen - VcCounterLen - Iz Len - -sechdr - sectrlr - ocflen - fecflen ; sechdr/sectrlr will be 0 len for OID frames
                        bool lptfSecHdrFlag; // expect security header?
                        bool lptfSecTrlrFlag; // expect security trailer?
                        if ( ptfIsOidFrame )
                        {
                            lptfSecHdrFlag = false; // not in OID frames
                            lptfSecTrlrFlag = false; // not in OID frames
                        }
                        else
                        {
                            lptfSecHdrFlag = lptfVcidptr->m_PresenceOfSpaceDataLinkSecurityHeader == ePresent?true:false; // expect security header?
                            lptfSecTrlrFlag = lptfVcidptr->m_PresenceOfSpaceDataLinkSecurityTrailer == ePresent?true:false; // expect security header?
                        }
                        int lptfSecHdrLen = lptfSecHdrFlag ? lptfVcidptr->m_LengthOfSpaceDataLinkSecurityHeader:0; // schdr len
                        int lptfSecTrlrLen = lptfSecTrlrFlag ? lptfVcidptr->m_LengthOfSpaceDataLinkSecurityTrailer:0; // schdr len
                        // bool lptfOcfFlag = lptfVcidptr->m_vc_include_OCF==eTrue?true:false; // expect ocf? (already boolean type)
                        int lptfOcfLen = ptfOcfFlag ? MAX_OCF_LENGTH : 0; // determine length
                        bool lptfIzFlag =  (lphyschanptr->m_Presence_of_Isochronous_Insert_Zone == ePresent && lphyschanptr->m_Isochronous_Insert_Zone_Length > 0) ? true : false; // expect IZ?
                        int lptfIzLen = lptfIzFlag ? lphyschanptr->m_Isochronous_Insert_Zone_Length : 0; // determine length
                        bool lptfFecfFlag = (lphyschanptr->m_Presence_of_Frame_Error_Control == ePresent)?true:false;
                        int lptfFecfLen = lptfFecfFlag ? lphyschanptr->m_Frame_Error_Control_Length : 0;
                        int lptfWholeTfdfLen = rxframelen - FRAME_HEADER_LENGTH - ptfVcSeqCounterOctets - lptfIzLen - lptfSecHdrLen - lptfSecTrlrLen - lptfOcfLen - lptfFecfLen;   

                        // klmprintf("klmocf vcid %d ocfflag %d ptfOcfFlag = %d\n",lptfVcidptr->m_VCID, lptfVcidptr->m_vc_include_OCF,ptfOcfFlag);fflush(stdout);
                        parseFrameFields(rxbuf, ptfLfirstOctetPastVcCounters,  // output frame and offset of first octet past frame header and vc frame counter to start parsing the rest of the frame
                                lptfIzFlag, lptfIzLen, ptfIzData,  // whether and what iz to nab
                                lptfSecHdrFlag, lptfSecHdrLen, ptfSecHdrData,  // no sc hdr on OID data
                                lptfWholeTfdfLen, ptfTfdfData,  ptfIsOidFrame, // tfdf len (everything leftover after removing known fields) - separate from ptfTfdfDataOnlyLen which does not include tfdf header (of which there is not one in oid frame)
                                lptfSecTrlrFlag, lptfSecTrlrLen, ptfSecTrlrData,  // no sc trlr on OID data
                                ptfOcfFlag, lptfOcfLen, ptfOcfData,  // whether and what ocf data to nab
                                lptfFecfFlag, lptfFecfLen, ptfFecfData);    // may be fecf on oid data since iz and ocf is used

                        //
                        // drop frame if bad security header or trailer
                        // Frame service frames (vcid and mcid) and OID frames don't have their lengths set by managed parameters and will default to 0 so frame service and oid frames are NOT checked for security header/trailer and won't be discarded for header/trailer mismatches
                        //
                        if ( lptfSecHdrFlag ) //  just report security trailer. normally it would be analyzed elsewhere
                        {
                            kprMutex.lock();printf("dTu HDR ");seedata(ptfSecHdrData,lptfSecHdrLen);printf("\n");fflush(stdout);kprMutex.unlock();
                        }
                        if ( lptfSecTrlrFlag ) // just report security trailer. normally it would be analyzed elsewhere
                        {
                            kprMutex.lock();printf("dTu TRL ");seedata(ptfSecTrlrData,lptfSecTrlrLen);printf("\n");fflush(stdout);kprMutex.unlock();
                        }
                        if ( lptfFecfFlag ) // just report the fecf. normally it would be analyzed elsewhere
                        {
                            kprMutex.lock();printf("dTu FEC ");seedata(ptfFecfData,lptfFecfLen);printf("\n");fflush(stdout);kprMutex.unlock();
                        }
                        if ( lptfSecHdrFlag ) // if there is a header in the non-OID frame
                        {
                            bool lpassSecurity = true;
                            if ( strncmp ( ( const char * ) lptfVcidptr->m_spaceDataLinkSecurityHeader, ( const char * ) ptfSecHdrData,lptfSecHdrLen) != 0 ) // check header 
                            {
                                kprMutex.lock();printf ( "mib expected sechdr " ); seedata ( lptfVcidptr->m_spaceDataLinkSecurityHeader, lptfSecHdrLen ); printf ( "\n" ); printf ( "rxd MISMATCH sechdr " ); seedata ( ptfSecHdrData,lptfSecHdrLen ); printf ( "\n" ); fflush(stdout);kprMutex.unlock();
                                lpassSecurity = false;
                            }
                            if ( lptfSecTrlrFlag ) // if there is a trailer (must be a header for there to be a trailer)
                            {
                                if ( strncmp ( ( const char * ) lptfVcidptr->m_spaceDataLinkSecurityTrailer, ( const char * ) ptfSecTrlrData,lptfSecTrlrLen) != 0 ) // check header 
                                {
                                    kprMutex.lock();printf ( "mib expected secTRL " ); seedata ( lptfVcidptr->m_spaceDataLinkSecurityTrailer, lptfSecTrlrLen ); printf ( "\n" ); printf ( "rxd MISMATCH secTRL " ); seedata ( ptfSecTrlrData,lptfSecTrlrLen ); printf ( "\n" ); fflush(stdout);kprMutex.unlock();
                                    lpassSecurity = false;
                                }
                            }
                            if ( ! lpassSecurity )
                            {
                                klmprintf ( "bad header or trailer - delivering bad frame to correct indication \n" ); fflush ( stdout ); // skip the parsing
                                //
                                // determine which indication you hafta call with this bad frame.
                                if ( verifyMAP_ID ( lphyschanptr->m_Name, lptfMasterchan,ptfVcid,ptfMapid ) ) // check to make sure this is good before you go off and deliver it
                                {
                                    //
                                    //
                                    // deliver what's in the reconstruction buffer right now
                                    //
                                    // call the frame type based indication to deliver what's in the current reconstruction buffer and then what's in THIS frame with a SDLS ERROR verification status flag value
                                    //
                                    gmapid lgmapid; // make a gmap for all the indications
                                    lgmapid.set(lphyschanptr->m_Name,ptfVersion_id,ptfSpacecraftId,ptfVcid,ptfMapid);
                                    kmapid *lmapptr = lphyschanptr->m_MCmap[lptfMasterchan]->m_vcidmap[ptfVcid]->m_mapmap[ptfMapid];
                                    if ( lmapptr->m_RxAssemblyIndex[ptfBypassFlag] > 0 ) // if a partial something in the buffer
                                    {
                                        // all partial dumps are the same
                                        // deliverPartialSDU resets m_RxAssemblyIndex[bypass] to zero
                                        lmapptr->deliverPartialSDU( lmapptr->m_RxAssemblyBuf[ptfBypassFlag], lmapptr->m_RxAssemblyIndex[ptfBypassFlag], eDumpingCurrentRxAssemblyBufDueToRxdSdlsError,ptfBypassFlag ); // deliver this partial packet you just received (if managed parameter says to) and leave m_RxAssemblyIndex[bypass] at 0
                                    }
                                    switch ( lmapptr->m_map_ServiceDataUnitType )
                                    {
                                        case eMAP_PACKET:
                                            lmapptr->mapp_indication(ptfTfdfData, lgmapid, 0, ptfBypassFlag, true /*true if error*/, SDLS_ERROR_verificationStatusCode);
                                            break;
                                        case eMAPA_SDU:
                                            lmapptr->mapasdu_indication(ptfTfdfData, lgmapid, ptfBypassFlag, false, SDLS_ERROR_verificationStatusCode);
                                            break;
                                        case eOCTET_STREAM:
                                            lmapptr->map_octetStream_indication(ptfTfdfData, lgmapid, false, SDLS_ERROR_verificationStatusCode);
                                            break;
                                    }
                                }
                                continue; // skip the rest of the frame and drop it
                            }
                        }
                        //	
                        // good frame with good security if it has security - deliver fields (iz, ocf, tfdf)
                        //	
                        if ( lphyschanptr->m_Isochronous_Insert_Zone_Length > 0 ) // if the MIB says there's an Insert Zone
                        {
                            if ( ptfIsOidFrame ) // never a loss flag on OID frames
                            {
                                lphyschanptr->deliverIZ ( ptfIzData, lphyschanptr->m_Isochronous_Insert_Zone_Length, false ); // never frame loss on OID frames
                            }
                            else // normal frame - pass Physchan iz loss flag
                            {
                                lphyschanptr->deliverIZ ( ptfIzData, lphyschanptr->m_Isochronous_Insert_Zone_Length, lphyschanptr->m_insertZoneLossFlag ); // REAL iz loss flag
                            }
                        }
                        if ( ptfOcfFlag == eTrue ) // if the frame says there's an OCF
                        {
                            // no ocf in oid if ( ptfIsOidFrame ) // never a loss flag on OID frames
                            // no ocf in oid {
                            // no ocf in oid lptfMasterchanptr->deliverOcfToMcOcfService ( ptfOcfData, lptfVcid , false ) ; // DO DELIVER TO THE MC 4.1.4.1.11 // never 'loss' flag on OID ocfs
                            // no ocf in oid }
                            // no ocf in oid else // normal frame - pass MC ocf loss flag
                            if ( !ptfIsOidFrame ) // if not an oid frame, deliver ocf
                            {
                                lptfMasterchanptr->deliverOcfToMcOcfService ( ptfOcfData, lptfVcid , lphyschanptr->m_MCmap[lptfMasterchan]->m_ocfLossFlag ) ; // DO DELIVER TO THE MC 4.1.4.1.11 // never 'loss' flag on OID ocfs
                            }
                        }
                        //
                        // handle TFDF datafield-and-header
                        //
                        if ( !ptfIsOidFrame ) // this is a normal vcid/mapid frame and NOT an OID frame. we drop OID frame data on the floor, aside from the iz and ocf
                        {
                            //
                            int lptfConstrRules, lptfProtocolId, lptfFhpLvo; // header stuff
                            unsigned char *lptfDfDataOnly; // pointer to data-only(noheader)
                            int lptfDfDataOnlyLen; // data-only(noheader) len
                            int ltfdfHeaderOctets = parseTFDFheader( ptfTfdfData, &lptfConstrRules, &lptfProtocolId, &lptfFhpLvo);
                            //
                            // deliver data field with parsed header params to SAP
                            // the deliver DataField function will do the work of knowing which PVN it goes to, if it's a packet
                            //
                            // can't know pvn until parse individual packets
                            lptfDfDataOnly = &ptfTfdfData[ltfdfHeaderOctets]; // point at first octet past header
                            lptfDfDataOnlyLen = lptfWholeTfdfLen - ltfdfHeaderOctets; // total octets minus header
                            kprMutex.lock();printf ( "delivering const rules %s data to physchan %s MC %d vcid %d mapid %d len %d <",crstr[lptfConstrRules], lphyschanptr->m_Name.c_str(), lptfMasterchan, lptfVcid, lptfMapid , lptfDfDataOnlyLen); seedata(lptfDfDataOnly, lptfDfDataOnlyLen);printf(">\n");fflush ( stdout );kprMutex.unlock();
                            lptfMapidptr->deliverDataField ( lptfConstrRules, lptfProtocolId,  lptfFhpLvo , lptfDfDataOnly, lptfDfDataOnlyLen ,ptfProtocolCommandControlFlag, ptfBypassFlag );  // also pass along the seqeunceControl0expedited1-valued ptfBypassFlag
                        }
                        // after having delivered everything, turn off flag for next time
                        lptfMapidptr->m_frameCountError = false;
                        lptfMapidptr->errstats(); // give it this frame's mapid pointer
                    }
                }
#else // PTFBITFIELDREWRITTEN
                // check to see if entire frame is normal (NOT an OID idle fill frame and NOT a truncated frame)
                bool ltruncatedFrame = false;
                bool loidFrame = false;
                int lsecurityHeaderLen;
                unsigned char *ucp_vcidsecheader;
                unsigned char *ucp_vcidsectrailer;
                int lsecurityTrailerLen;
                bool lgoodFrame; // not truncated and not vcid 63 OID
                lgoodFrame = mibParseFrame ( lphyschanptr, rxbuf, rxframelen , &ltruncatedFrame, &loidFrame); // parse the frame for this physical channel
                //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// fastbit
                if ( ! lgoodFrame ) // could return false from bad vcid/map or bad-scid-when-destination-bit-is-set(e.g. this frame's destination is supposed to be ME but the scid says it isn't)
                {
                    continue;
                }
                int lmasterchan = (m_version_id * 65536) + m_scid;
                int lvcid = m_vcid; // depending on the setting in the VCID
                int lmapid = m_mapid;
                //
                // handle OID frame
                //
                if ( loidFrame )
                {
                    //
                    // note - in OID frames the security header/trailer are not looked for so the frame is not dropped-because-of-a-bad-security-header/trailer
                    //
                    // deliver iz and OCF if managed-parameter-included and flagged
                    //
                    // physchan will always exist because you just rxd on it, so no need to verify physchan
                    // handle insert zone (which can be in normal frame or oid frame but never truncated frame)
                    if ( lphyschanptr->m_Isochronous_Insert_Zone_Length > 0 ) // if the MIB says there's an Insert Zone
                    {
                        lphyschanptr->deliverIZ ( m_izData, lphyschanptr->m_Isochronous_Insert_Zone_Length, false ); // never frame loss on OID frames
                    }
                    if ( m_ocfPresent != 0 ) // if the frame says there's an OCF
                    {
                        lMCidptr->deliverOcfToMcOcfService ( m_ocfData, lvcid ,false ) ; // DO DELIVER TO THE MC 4.1.4.1.11 // never 'loss' flag on OID ocfs
                    }
                    klmprintf ( "DROPPING OID frame on %s\n",lphyschanptr->m_Name.c_str() ); fflush ( stdout );
                }
                // handle truncated frame
                else if ( ltruncatedFrame ) 
                {
                    // transfer frame header is 4 bytes, transfer frame data field header is 1 byte
                    if ( verifyMAP_ID ( lphyschanptr->m_Name, lmasterchan,lvcid,lmapid ) ) // check to make sure this is good before you go off and deliver it
                    {
                        klmprintf ( "delivering %d-octet protId %d TRUNCATED data to physchan %s MC %d vcid %d mapid %d\n",m_dfDataOnlyLen, m_protocolId, lphyschanptr->m_Name.c_str(), lmasterchan,lvcid,lmapid ); fflush ( stdout );
                        lmapidptr->deliverRawDataFromTruncatedFrame(lphyschanptr->m_Name, lmasterchan, m_dfDataOnly ); // deliver protId & data
                    }
                    else
                    {
                        reportUndeliverableMapId ( lphyschanptr->m_Name, lmasterchan,lvcid,lmapid );
                    }
                }
                //
                // handle normal frame
                //
                else 
                {
                    // 
                    lsecurityHeaderLen = lvcidptr->m_LengthOfSpaceDataLinkSecurityHeader; // local copy makes it easy to work with
                    lsecurityTrailerLen = lvcidptr->m_LengthOfSpaceDataLinkSecurityTrailer; // local copy makes it easy to work with
                    ucp_vcidsecheader = lvcidptr->m_spaceDataLinkSecurityHeader; // this is per-vcid now
                    ucp_vcidsectrailer = lvcidptr->m_spaceDataLinkSecurityTrailer;
                    //
                    // drop frame if bad security header or trailer
                    // Frame service frames (vcid and mcid) and OID frames don't have their lengths set by managed parameters and will default to 0 so frame service and oid frames are NOT checked for security header/trailer and won't be discarded for header/trailer mismatches
                    //
                    if ( lsecurityHeaderLen > 0 || lsecurityTrailerLen > 0 ) // if either a header or a trailer
                    {
                        if ( strncmp ( ( const char * ) ucp_vcidsecheader, ( const char * ) m_secHdrData,lsecurityHeaderLen ) != 0 // check both
                                ||
                                strncmp ( ( const char * ) ucp_vcidsectrailer, ( const char * ) m_secTrlrData,lsecurityTrailerLen ) != 0
                           )
                        {
                            kprMutex.lock();printf ( "mib mismatch sechdr " ); seedata ( ucp_vcidsecheader,lsecurityHeaderLen ); printf ( "\n" ); printf ( "         rxd sechdr " ); seedata ( m_secHdrData,lsecurityHeaderLen ); printf ( "\n" ); printf ( "mib sectrlr " ); seedata ( ucp_vcidsectrailer, lsecurityTrailerLen ); printf ( "\n" ); printf ( "rxd sectrlr " ); seedata ( m_secTrlrData,lsecurityTrailerLen ); printf ( "\n" );fflush(stdout);kprMutex.unlock();
                            badSecurityHeaderTrailer();
                            continue; // skip the rest of the frame and drop it
                        }
                    }
                    if ( verify_MC_ID ( lphyschanptr->m_Name,lmasterchan ) ) // good mcid
                    {
                        if ( lMCidptr->m_mcFrameService ) // if this is a mcFrameService mcid
                        {
                            seeEverything();
                            // deliver entire frame to mc frame service on this mcid
                            lMCidptr->deliverMcFrameServiceFrame ( lphyschanptr->m_Name, rxbuf,rxframelen );
                        }
                        else // not a mcFrameService mcid, already verified physchan & mcid, just verify vcid and mapid
                        {
                            if ( verifyMAP_ID ( lphyschanptr->m_Name, lmasterchan,lvcid,lmapid ) ) // check to make sure this is good before you go off and deliver it
                            {
                                //
                                // copy this mapid ptr
                                //
                                if ( lvcidptr->m_VcidFrameService ) // this is a vcid frame service vcid
                                {
                                    lvcidptr->deliverVcidFrameServiceFrame ( lphyschanptr->m_Name, lmasterchan, rxbuf,rxframelen );
                                }
                                else if ( lvcidptr->m_CopService ) // this is a COP service vcid
                                {
                                    froggy compiler warning generator lvcidptr->deliverCopServiceFrame ( lphyschanptr->m_Name, lmasterchan, rxbuf, rxframelen, lvcidptr->m_COP_in_Effect );
                                }
                                else // this is not a vcid frame service frame - may be OID
                                {
                                    if ( !loidFrame ) // NOT an OID frame  - vcid has already been validated  - deliver data
                                    {
                                        kprMutex.lock();printf ( "delivering data to physchan %s MC %d vcid %d mapid %d len %d <",lphyschanptr->m_Name.c_str(), lmasterchan, lvcid, lmapid , m_dfDataOnlyLen); seedata(m_dfDataOnly, m_dfDataOnlyLen);printf(">\n");fflush ( stdout );kprMutex.unlock();
                                        //
                                        // deliver data field with parsed header params to SAP
                                        // the deliver DataField function will do the work of knowing which PVN it goes to, if it's a packet
                                        //
                                        // can't know pvn until parse individual packets
                                        lmapid_ptr->deliverDataField ( m_constrRules, m_protocolId,  m_fhpLvo , m_dfDataOnly, m_dfDataOnlyLen,lklmsequenceControl0expedited1  ); 
                                    }
                                    // handle OCF (which will never be in truncated frame but may be in OID frame or normal frame)
                                    if ( m_ocfPresent > 0 ) // if the FRAME says there is an ocf
                                    {
                                        klmprintf ( "delivering ocf to %s\n",lvcidptr->vcktree()); fflush ( stdout );
                                        lMCidptr->deliverOcfToMcOcfService ( m_ocfData, lvcid , lMCidptr->m_ocfLossFlag ) ; // DO DELIVER TO THE MC 4.1.4.1.11
                                    }
                                    else
                                    {
                                        klmprintf ( "------- NO ocf -------\n" ); fflush ( stdout );
                                    }
                                    // physchan will always exist because you just rxd on it, so no need to verify physchan
                                    // handle insert zone (which can be in normal frame or oid frame but never truncated frame)
                                    if ( lphyschanptr->m_Isochronous_Insert_Zone_Length > 0 ) // if the MIB says there's an Insert Zone
                                    {
                                        lphyschanptr->deliverIZ ( m_izData, lphyschanptr->m_Isochronous_Insert_Zone_Length , lphyschanptr->m_insertZoneLossFlag );
                                    }
                                }
                                // after having delivered everything, turn off flag for next time
                                lmapid_ptr->m_frameCountError = false;
                            }
                            else
                            {
                                reportUndeliverableMapId ( lphyschanptr->m_Name, lmasterchan,lvcid,lmapid );
                            }
                        }
                    }
                    lmapidptr->errstats(); // give it this frame's mapid pointer
                }
#endif // PTFBITFIELDREWRITTEN
            }
            // pthread_exit(NULL);
        }
        void reportUndeliverableMapId ( String & physchan, int lmasterchan,int lvcid,int lmapid )
        {
            klmprintf ( "rxd undeliverable mapid on physchan %s masterchan %d vcid %d mapid %d\n",physchan.c_str(),lmasterchan,lvcid,lmapid );
            fflush ( stdout );
        }
        /*void trx(void)
          {
          m_rxthread = new mibRxThread(this);
          }
          */
        /*
           void THIS_IS_NEVER_CALLED_BY_ANYBODY_vcidReleaseTimeoutOidTx(String PC, int MCid, int vc)
           {
           kphysicalChannel *lPCptr;
           kvcid *lvcidptr;

           lPCptr = pcmap[PC];
           if ( lPCptr != NULL )
           {
           if ( lPCptr->m_pchan_Generate_OID_Frame == eTrue )  // no need to generate OID frame if physchan says don't
           {
           if ( lPCptr->m_MCmap[MCid] != NULL )
           {
           lvcidptr = lPCptr->m_MCmap[MCid]->m_vcidmap[vc];
           if ( lvcidptr != NULL )
           {
           if ( lPCptr->m_pc_Transfer_Frame_Type == eFixed ) // only tx OID frame if pc frametype is fixed (4.1.3.2 and 9/29/2017 3:59pm email by ed greenberg)
           {
        // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frames lvcidptr->getVcidOcfBuf(locfData,&locfDataLen); // mutex-get ocf buf
        // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frames
        // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID framesunsigned char locfData[MAX_OCF_LENGTH];
        // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID framesint locfDataLen;
        // feed ocf to physchan OID frame txer
        kvcid *lOIDptr = lPCptr->m_MCmap[MCid]->m_vcidmap[63]; // get a pointer at this MC's corresponding OID vcid (won't get here from mc/vc frame service frames becuasse their timers aren't checked)
        // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frameslPCptr->txOIDframe(locfData,locfDataLen,MCid,lOIDptr->getVcFrameCounterOctets(eExpedited),lOIDptr->getVcFrameCounterAndInc(eExpedited)); // tx the idle frame specified in 4.1.4.1.6 
        lPCptr->txOIDframe(MCid,lOIDptr->getVcFrameCounterOctets(eExpedited),lOIDptr->getVcFrameCounterAndInc(eExpedited)); // tx the idle frame specified in 4.1.4.1.6 
        // klm918 decrementedUponGet() lvcidptr->decrementMCidOcfDeliveryCount(); // decrement the delivery count of the OCF since you may have just delivered it
        }
        //
        // ALWAYS bump the vcOidTimeToTx timer of the vcid whose oid timer expired out by the release time 
        //
        if ( lvcidptr->m_timedVcidReleasesFlag )
        {
        // lvcidptr->m_vcidUsTimeToTxMinTimeBetweenVcidFrames = globalUsTimeNow + (lvcidptr->m_Maximum_delay_in_milliseconds_between_releases_of_frames_of_the_same_VC * 1000); // dealing in microseconds
        lvcidptr->m_vcidUsTimeToTxMinTimeBetweenVcidFrames = globalUsTimeNow + (lvcidptr->m_Maximum_delay_in_milliseconds_between_releases_of_frames_of_the_same_VC); // dealing in microseconds
        }
        }
        }
        }
        }
        }
        */
        //
        //
        //  for tx-whatcha-rx
        // 
        //
        bool map_MIB_P_Request ( unsigned char * onlyDataNoHeader, int onlyDataNoHeaderLen, gmapid_t gmapid, int packetVersionNumber, int ltxSDU_ID, int sequenceControl0expedited1 ); // tx whatcha rx
        void map_MIB_MapaSDU_Request ( unsigned char * mapaSdu, int onlyDataNoHeaderLen,/* restored 20180522 mapa_sdu length replaced oct30,2017 with managed mapid parameter m_map_mapaSduLength */ gmapid_t GMAPID, int ltxSDU_ID, int sequenceControl0expedited1); // tx whatcha rx
        void map_MIB_OctetStream_Request ( unsigned char * onlyDataNoHeader, /* int onlyDataNoHeaderLen replaced oct 30,2017 with managed mapid parameter m_map_octetStreamRequestLength*/ gmapid_t gmapid/*2/25/2018 4:25pm greg kazz email removes this param, int sequenceControl0expedited1*/); // tx whatcha rx
        void MIB_insert_request ( unsigned char *izdata, String physchan); // tx whatcha rx
        void MIB_ocfServiceRequest ( unsigned char * ocfRq, gvcid_t gvcid ); // tx whatch rx
        // 
        // after you've made the header, build the frame out of its component parts, add the length
        // 
        void copAsync_NotifyIndication(gvcid GVCID, int anType, int noQual )
        {
            char *s;
            switch (anType)
            {
                case 0: s = (char *)"Alert ";
                        break;
                case 1: s = (char *)"Suspend";
                        break;
                default: s = (char *)"ERROR in cycling through anTypes";
                         break;
            }
            klmprintf("copAsync_NotifyIndication for %s/%d/%d notification type %s notQualifier %d \n",GVCID.PHYSCHAN.c_str(),(GVCID.TFVN * 65536) + GVCID.SCID, GVCID.VCID, s,noQual);fflush(stdout);
        }
        void copDirectiveNotifyIndication(gvcid GVCID, int copDirectiveId, int directiveNotifyNotificationType )
        {
            char *s;
            switch (directiveNotifyNotificationType)
            {
                case 0: s = (char *)"Accept response to directive";
                        break;
                case 1: s = (char *)"Reject response to directive";
                        break;
                case 2: s = (char *)"Postive Confirm response to directive";
                        break;
                case 3: s = (char *)"Negative Confirm response to directive";
                        break;
                default: s = (char *)"ERROR in cycling through directives";
                         break;
            }
            klmprintf("copDirectiveNotifyIndication for GVCID %s/%d/%d directive id %d notification type %s\n",GVCID.PHYSCHAN.c_str(),(GVCID.TFVN * 65536) + GVCID.SCID, GVCID.VCID,copDirectiveId,  s);fflush(stdout);
        }
        void copDirectiveNotifyIndication(int portId, int copDirectiveId, int directiveNotifyNotificationType )
        {
            char *s;
            switch (directiveNotifyNotificationType)
            {
                case 0: s = (char *)"Accept response to directive";
                        break;
                case 1: s = (char *)"Reject response to directive";
                        break;
                case 2: s = (char *)"Postive Confirm response to directive";
                        break;
                case 3: s = (char *)"Negative Confirm response to directive";
                        break;
                default: s = (char *)"ERROR in cycling through directives";
                         break;
            }
            klmprintf("copDirectiveNotifyIndication for PortID %d directive id %d notification type %s\n",portId, copDirectiveId,  s);fflush(stdout);
        }
        void copDirectivePortIdRequest(int portId, int copDirectiveId, int copDirectiveType, int copDirectiveQualifier) // message from cop to cop on other end.
        {
            static int lportIdStaticDirectiveNotifyNotificationType = 3;
            //
            // "scan" through valid gvcids and see which one has cop enabled
            // (for our purposes here, i'll just declare a known good one)
            //
            bool foundone = false;
            std::map <String,kphysicalChannel *>::iterator l_physchanit; // local iterators
            std::map <int, kmasterChannel *>::iterator l_mc_it;
            std::map <int, kvcid *>::iterator l_vcidit;
            std::map <int, kmapid *>::iterator l_mapit; // for scanning through map ids
            for ( l_physchanit = pcmap.begin(); l_physchanit != pcmap.end() && !foundone; l_physchanit++ ) // always start from beginning
            {
                kphysicalChannel *lpcptr = l_physchanit->second;
                for ( l_mc_it = lpcptr->m_MCmap.begin(); l_mc_it != lpcptr->m_MCmap.end() && !foundone; l_mc_it++ ) // always start from beginning
                {
                    for ( l_vcidit = l_mc_it->second->m_vcidmap.begin(); l_vcidit != l_mc_it->second->m_vcidmap.end() && !foundone; l_vcidit++ ) // always start from beginning
                    {
                        kvcid *lptrvcid = l_vcidit->second;
                        if ( lptrvcid->m_COP_in_Effect == CopPInEffect ) // found a vcid with copP in effect
                        {
                            foundone = true; // break out of the loop
                            l_mapit = l_vcidit->second->m_mapmap.begin();  // get the first mapid
                            int lmapid = 0; // since cop only supplies GVCID, use default mapid 0
                            // build a frame with the dirid, dirtype, and dirqual in octets 0,1,2 then ship that puppy
                            charint lca;
                            unsigned char lframe[MAX_FRAME_SIZE];
                            int lbypass = eExpedited;  // hardcoded all cop directives to be expedited instead of using lptrvcid->m_mapmap[lmapid]->m_txBypassFlag;
                            int lfco = lptrvcid->getVcFrameCounterOctets(lbypass);
                            int lfcai = lptrvcid->getVcFrameCounterAndInc(lbypass);
                            int lframelenSoFar = makeTransferFrameHeaderNoLen( 
                                    (unsigned char *)lframe, 
                                    lpcptr->m_Transfer_Frame_Version_Number,
                                    l_mc_it->second->m_MC_SpacecraftId,
                                    0, // source m_myVcidParent->m_source0Destination1,
                                    lptrvcid->m_VCID,
                                    lmapid,
                                    0, // endOfTransferFrameHeader
                                    lbypass,
                                    1, // here this will ALWAYS be 1(protocol data) m_protocolCommandControlFlag, // protocolCommandControlFlag 0=user data 1=protocol data
                                    0, // no ocf
                                    lfco, // vcSeqCounterOctets
                                    lfcai // vcSequenceCount // fastbit
                                    );
                            // add dir id, dir type, and dir qualifier, each assumed to be < 256
                            lframe[lframelenSoFar++] = (unsigned char) 0xe2; // construction rule 111 upid 00010 for cop-P as per 4.1.4.2.3.3
                            lca.i = copDirectiveId;
                            lframe[lframelenSoFar++] = lca.c[0];
                            lca.i = copDirectiveType;
                            lframe[lframelenSoFar++] = lca.c[0];
                            lca.i = copDirectiveQualifier;
                            lframe[lframelenSoFar++] = lca.c[0];
                            lca.i = portId;
                            lframe[lframelenSoFar++] = lca.c[0];
                            memcpy(&lframe[lframelenSoFar], "frog",4); // copy dummy crc into cop frame
                            lframelenSoFar += 4; // adjust frame len for crc inclusion
                            //
                            // if this is a fixed length frame, idle fill after the CRC
                            //
                            if ( lptrvcid->m_vcid_Transfer_Frame_Type == eFixed ) // fixed frame - need to idle fill
                            {
                                // idlefill until end ( total frame len - lensofar (which includes header, vc fc octets, and tfdf))
                                idleFillHere(&lframe[ lframelenSoFar ], lpcptr->m_pc_Transfer_Frame_Length - lframelenSoFar, lpcptr->m_pcOIDdata);  
                                lframelenSoFar = lpcptr->m_pc_Transfer_Frame_Length; // add the idle bytes to frame length
                            }
                            // add len
                            lca.i = lframelenSoFar - 1; // length in frame is totallen-1
                            lframe[4] = lca.c[1];
                            lframe[5] = lca.c[0];
                            pcmap[lpcptr->m_Name]->txFrame ( lframe,lframelenSoFar,lptrvcid->m_Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_COP_control_commands); // number of cop repeititons (limited by physchan reps value in readMibParameters())
                        }
                    }
                }
            }
            if ( !foundone)
            {
                klmprintf("copDirectivePortIdRequest ERROR for portId %d = no valid gvcid found with cop P in effect. directive id %d not sent\n",portId,copDirectiveId);fflush(stdout);
            }
            //
            // call fake directive_notify.indication as a result of this directive request
            //
            copDirectiveNotifyIndication(portId, copDirectiveId, ++lportIdStaticDirectiveNotifyNotificationType %= 4);
        }
        void copDirectiveRequestVCID( int copDirectiveId, gvcid GVCID, int copDirectiveType, int copDirectiveQualifier) // message from cop to cop on other end.
        {
            static int lstaticDirectiveNotifyNotificationType = 3;
            int lagmcid = (GVCID.TFVN * 65536) + GVCID.SCID;
            if ( verifyVCID ( GVCID.PHYSCHAN, lagmcid, GVCID.VCID ) ) // valid gvcid
            {
                unsigned char locfData[5];
                int locfDataLen = 0;
                kphysicalChannel *lpcptr = pcmap[GVCID.PHYSCHAN];
                // verify that this is the COP SERVICE SAP vcid
                kvcid *lptrvcid = pcmap[GVCID.PHYSCHAN]->m_MCmap[lagmcid]->m_vcidmap[GVCID.VCID];
                if ( lptrvcid->m_COP_in_Effect == CopOneInEffect ) // some cop IS in effect and it's gotta be the VCID cop
                {
                    lptrvcid->getVcidOcfBuf(locfData,&locfDataLen);
                    int lmapid = 0; // since cop only supplies GVCID, use default mapid 0
                    // build a frame with the dirid, dirtype, and dirqual in octets 0,1,2 then ship that puppy
                    charint lca;
                    unsigned char lframe[MAX_FRAME_SIZE];
                    int lbypass = eExpedited;  // hardcoded all cop directives to be expedited instead of using lptrvcid->m_mapmap[lmapid]->m_txBypassFlag;
                    int lfco = lptrvcid->getVcFrameCounterOctets(lbypass);
                    int lfcai = lptrvcid->getVcFrameCounterAndInc(lbypass);
                    int lframelenSoFar = makeTransferFrameHeaderNoLen( 
                            (unsigned char *)lframe, 
                            GVCID.TFVN,
                            GVCID.SCID,
                            0, // source m_myVcidParent->m_source0Destination1,
                            GVCID.VCID,
                            lmapid,
                            0, // endOfTransferFrameHeader
                            lbypass,
                            1, // here this will ALWAYS be 1(protocol data) m_protocolCommandControlFlag, // protocolCommandControlFlag 0=user data 1=protocol data
                            locfDataLen==0?0:1, // MAY BE an ocf
                            lfco, // vcSeqCounterOctets
                            lfcai // vcSequenceCount // fastbit
                            );
                    // add dir id, dir type, and dir qualifier, each assumed to be < 256
                    lframe[lframelenSoFar++] = (unsigned char) 0xe1; // construction rule 111 upid 00001 for cop-1 as per 4.1.4.2.3.3
                    lca.i = copDirectiveId;
                    lframe[lframelenSoFar++] = lca.c[0];
                    lca.i = copDirectiveType;
                    lframe[lframelenSoFar++] = lca.c[0];
                    lca.i = copDirectiveQualifier;
                    lframe[lframelenSoFar++] = lca.c[0];
                    lca.i = 'x'; // no Port ID
                    lframe[lframelenSoFar++] = lca.c[0];
                    memcpy(&lframe[lframelenSoFar], "frog",4); // copy dummy crc into cop frame
                    lframelenSoFar += 4; // adjust frame len for crc inclusion
                    //
                    // if this is a fixed length frame, idle fill after the CRC (lframelenSoFar INCLUDES header and vc frame counter octets)
                    //
                    if ( lptrvcid->m_vcid_Transfer_Frame_Type == eFixed ) // fixed frame - need to idle fill
                    {
                        // idlefill until end ( total frame len - lensofar (which includes header, vc fc octets, and tfdf))
                        idleFillHere(&lframe[ lframelenSoFar ], lpcptr->m_pc_Transfer_Frame_Length - lframelenSoFar, lpcptr->m_pcOIDdata);  
                        lframelenSoFar = lpcptr->m_pc_Transfer_Frame_Length; // add the idle bytes to frame length
                    }
                    // add len
                    lca.i = lframelenSoFar - 1; // length in frame is totallen-1
                    lframe[4] = lca.c[1];
                    lframe[5] = lca.c[0];
                    // transmitted immediatley instead of queued
                    pcmap[GVCID.PHYSCHAN]->txFrame ( lframe,lframelenSoFar,lptrvcid->m_Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_COP_control_commands); // COP repetitions (limited by physchan param)
                }
                else
                {
                    klmprintf("copDirectiveRequestVCID ERROR = cop-1 called but copineffect setting was %d for gvcid %s/%d/%d. directive id %d not sent\n",lptrvcid->m_COP_in_Effect, GVCID.PHYSCHAN.c_str(),lagmcid,GVCID.VCID,copDirectiveId);fflush(stdout);
                }
                //
                // call fake directive_notify.indication as a result of this directive request
                //
                copDirectiveNotifyIndication(GVCID, copDirectiveId, ++lstaticDirectiveNotifyNotificationType %= 4);
            }
        }
        void copAsyncNotifyIndication(gvcid GVCID, int portId, int notificationType, int notificationQualifier){}; // message from cop to cop on other end.
        void reportClcwRateToCop(gvcid GVCID,String clcwreportingrate)
        {
            // klmprintf("reportClcwRateToCop gvcid %s/%d/%d clcw reporting rate of %s\n",GVCID.PHYSCHAN.c_str(),(GVCID.TFVN * 65536) + GVCID.SCID, GVCID.VCID,clcwreportingrate.c_str());fflush(stdout);
        }
    private:
        CircularPacketQueue * m_qToDo; // stuff todo
        PMutex m_qToDo_mutex;
};

class mibRxThread:public PThread
{
    friend class mibclass;
    public:
    mibRxThread ( void* arg = NULL ) : PThread ( arg ) {  }
    mibclass m_mib;

    void mrxPutDeliverFn( void (*thefn)(unsigned char *, int, int ), String physchan, int tfvn, int scid, int vcid, int mapid)
    {
        m_mib.mibPutDeliverFn( thefn, physchan, tfvn, scid, vcid, mapid);
    }
    void mrxPutFarmFn( bool (*thefn)( int ), String physchan, int tfvn, int scid, int vcid)
    {
        m_mib.mibPutFarmFn( thefn, physchan, tfvn, scid, vcid);
    }
    void readMibConfig(char *filename)
    {
        m_mib.readMibConfig(filename);
    }
    void mibGetMcOcf ( String physchan, int tfvn, int scid, unsigned char *ocf, int *ocflen)
    {
        m_mib.mibGetMcOcf ( physchan, tfvn, scid, ocf, ocflen);
    }
    void killthisPutVcFrameDropper(String physchan, int tfvn, int scid, int vcid, int dropN, int dropEveryN )
    {
        m_mib.killthisMibPutVcFrameDropper(physchan, tfvn, scid, vcid, dropN, dropEveryN ) ;
    }
    void mrxPutGIVEWHOLEFRAMEFN( void (*thefn)(unsigned char *, int ))
    {
        m_mib.putGIVEWHOLEFRAMEFN(thefn);
    }
    void dumpConfigs( void )
    {
        m_mib.dumpConfigs();
    }
    void * run(void *arg)
    {
        m_mib.rx();
        return NULL;
    }
};
extern mibclass MIB;
int mibclass::enumServiceData ( String & par )
{
    int retval = eMAP_PACKET;
    if ( strcasecmp ( par.c_str(),"packet" ) == 0 ) // matches fixed
    {
        retval = eMAP_PACKET;
    }
    else if ( strcasecmp ( par.c_str(),"mapa_sdu" ) == 0 ) // matches variable
    {
        retval = eMAPA_SDU;
    }
    else if ( strcasecmp ( par.c_str(),"octet_stream" ) == 0 ) // matches variable
    {
        retval = eOCTET_STREAM;
    }
    else
    {
        klmprintf ( "Service Data value error %s\n",par.c_str() );
    }
    fflush ( stdout ); // TODO handle config error
    return retval;
}
int mibclass::enumFixedVariable ( String & par )
{
    int retval = eVariable;
    if ( strcasecmp ( par.c_str(),"fixed" ) == 0 ) // matches fixed
    {
        retval = eFixed;
    }
    else if ( strcasecmp ( par.c_str(),"variable" ) == 0 ) // matches variable
    {
        retval = eVariable;
    }
    else
    {
        klmprintf ( "FIXED VARIABLE value error %s\n",par.c_str() );
    }
    fflush ( stdout ); // TODO handle config error
    return retval;
}
char * mibclass::strTrueFalse ( int tf )
{
    return tf == eTrue? ( char * ) "True": ( char * ) "False";
}
char * mibclass::strFixedVariable ( int fv )
{
    return fv == eFixed? ( char * ) "Fixed": ( char * ) "Variable";
}
const char * mibclass::strServiceData ( int fv )
{
    const char * cp;
    switch ( fv )
    {
        case eMAP_PACKET:
            cp = "Packet";
            break;
        case eMAPA_SDU:
            cp = "Map_SDU";
            break;
        case eOCTET_STREAM:
            cp = "Stream Data";
            break;
        default:
            cp = "ILLEGAL VALUE";
            break;
    }
    return cp;
}
char * mibclass::strPresentAbsent ( int pa )
{
    return pa == ePresent? ( char * ) "Present": ( char * ) "Absent";
}
int mibclass::enumTrueFalse ( String & par )
{
    int retval = eFalse;
    if ( strcasecmp ( par.c_str(),"true" ) == 0 ) // matches fixed
    {
        retval = eTrue;
    }
    else if ( strcasecmp ( par.c_str(),"false" ) == 0 ) // matches variable
    {
        retval = eFalse;
    }
    else
    {
        klmprintf ( "True False value error parameter %s\n",par.c_str() );
    }
    fflush ( stdout ); // TODO handle config error
    return retval;
}
int mibclass::enumPresentAbsent ( String & par )
{
    int retval = eAbsent;
    if ( strcasecmp ( par.c_str(),"present" ) == 0 ) // matches fixed
    {
        retval = ePresent;
    }
    else if ( strcasecmp ( par.c_str(),"absent" ) == 0 ) // matches variable
    {
        retval = eAbsent;
    }
    else
    {
        klmprintf ( "Present Absent value error\n" );
    }
    fflush ( stdout ); // TODO handle config error
    return retval;
}
int mibclass::kintval ( String & str )
{
    return atoi ( str.c_str() );
}
char * mibclass::skipWhitespace ( char * cp )
{
    while ( ( *cp < '!' || *cp > '~' ) && *cp != '\0' )
    {
        cp++;  // not printable and not nul - notfound yet
    }
    return cp;
}
char * mibclass::findWhitespace ( char * cp )
{
    while ( ( *cp >= '!' && *cp <= '~' ) && *cp != '\0' )
    {
        cp++;  // IS printable and not nul - skip
    }
    return cp;
}
char * mibclass::findNum ( char * cp )
{
    while ( ( *cp < '0' || *cp > '9' ) && *cp != '\0' )
    {
        cp++;  // not 0-9 and not nul
    }
    return cp;
}
char * mibclass::findNonNum ( char * cp )
{
    while ( ( *cp >= '0' && *cp <= '9' ) && *cp != '\0' )
    {
        cp++;  // not printable and not nul
    }
    return cp;
}
void mibclass::parse10params ( char * line ) // at least 10 parameters all are null when the line runs out
{
    int whichparam = 0;
    char * starthere = line;
    char * stophere;
    char lstr[65536];
    while ( whichparam < 10 )
    {
        param[whichparam].clear();
        starthere = skipWhitespace ( starthere ); // find start of parameter
        stophere = findWhitespace ( starthere );
        memcpy ( lstr,starthere, ( stophere-starthere ) );
        lstr[stophere - starthere] = '\0';
        param[whichparam].append ( lstr );
        whichparam++;
        starthere = stophere;
    }
}
bool mibclass::verifyPhysChan ( String & physchan )
{
    bool retval = false;
    std::map <String,kphysicalChannel *>::iterator search = pcmap.find ( physchan ); // see if physchan object already exists
    if ( search != pcmap.end() ) // make sure there is one
    {
        retval = true;
    }
    return retval;
}
bool mibclass::verify_MC_ID ( String & physchan, int mc_id )
{
    int retval = false;
    if ( verifyPhysChan ( physchan ) ) // legal physchan
    {
        if ( mc_id >= 0 && mc_id < MAX_MASTER_CHANNEL_IDS ) // legal MC_ID if illegal it won't find it either
        {
            std::map <int,kmasterChannel *>::iterator search = pcmap[physchan]->m_MCmap.find ( mc_id ); // see if  mc_id object already exists
            if ( search != pcmap[physchan]->m_MCmap.end() ) // make one if it doesn't exist, replace it if it does
            {
                retval = true;
            }
        }
    }
    return retval;
}
bool mibclass::verifyVCID ( String & physchan, int mc_id, int vcid )
{
    int retval = false;
    if ( verify_MC_ID ( physchan, mc_id ) ) // physchan-with-this-mc_id exists
    {
        if ( vcid >= 0 && vcid < MAX_VCIDS ) // legal vcid // if illegal it won't find it either
        {
            if ( vcid == 63 )
            {
                retval = true; // 63 is a valid vcid
            }
            else // gotta check if the vcid is in the MC vcid map
            {
                std::map <int,kvcid *>::iterator search = pcmap[physchan]->m_MCmap[mc_id]->m_vcidmap.find ( vcid ); // see if vcid object already exists
                if ( search != pcmap[physchan]->m_MCmap[mc_id]->m_vcidmap.end() ) // make one if it doesn't exist, replace it if it does
                {
                    retval = true;
                }
            }
        }
    }
    return retval;
}
// allow for vcid 63 making map_id irrelevant
bool mibclass::verifyMAP_ID ( String & physchan, int mc_id, int vcid,int map_id )
{
    int retval = false;
    if ( verifyVCID ( physchan, mc_id, vcid ) ) // physchan-with-this-mc_id-with-this-vcid exists
    {
        if ( vcid == 63 )
        {
            retval = true;
        }
        else
        {
            if ( map_id >= 0 && map_id < MAX_MAP_IDS ) // legal vcid // if illegal it won't find it either
            {
                std::map <int,kmapid *>::iterator search = pcmap[physchan]->m_MCmap[mc_id]->m_vcidmap[vcid]->m_mapmap.find ( map_id ); // see if vcid object already exists
                if ( search != pcmap[physchan]->m_MCmap[mc_id]->m_vcidmap[vcid]->m_mapmap.end() ) // make one if it doesn't exist, replace it if it does
                {
                    retval = true;
                }
            }
        }
    }
    return retval;
}
kmapid * mibclass::findMap ( String physchan, int MCid, int vcid,int mapid ) // gotta have all these parameters to find the map
{
    std::map <String,kphysicalChannel *>::iterator physchanit;
    std::map<int, kmasterChannel *>::iterator mc_it;
    std::map<int, kvcid *>::iterator vcidit;
    std::map<int, kmapid *>::iterator mapit;


    physchanit = pcmap.find ( physchan );
    if ( physchanit != pcmap.end() ) // found physical channel
    {
        mc_it = physchanit->second->m_MCmap.find ( MCid );
        if ( mc_it != physchanit->second->m_MCmap.end() ) // scan master chans
        {
            vcidit=mc_it->second->m_vcidmap.find ( vcid );
            if ( vcidit != mc_it->second->m_vcidmap.end() )
            {
                mapit=vcidit->second->m_mapmap.find ( mapid );
                if ( mapit != vcidit->second->m_mapmap.end() )
                {
                    return mapit->second;
                }
            }
        }
    }
    return ( NULL );
}
void mibclass::kassignValids ( String & value,int oneMoreThanMaximumValue,bool * boollist )
{
    //
    // accepts a list of bools bool[MAX_VCIDS]; and a oneMoreThanMaximumValue like MAX_VCIDS=64 where the max is one more than the maximum value
    //
    char * intstart = ( char * ) value.c_str(); // point at first of value (should be list of delimited numbers)
    char * cp = intstart;
    char intstring[65536];
    int intval;
    while ( *cp != '\0' )
    {
        intstart = findNum ( cp );
        cp = findNonNum ( intstart ); // leave cp on a non num
        memcpy ( intstring,intstart, ( cp-intstart ) );
        intstring[cp - intstart] = '\0';
        intval = atoi ( intstring );
        if ( intval < oneMoreThanMaximumValue )
        {
            boollist[intval] = true;
        }
        else
        {
            klmprintf ( "range error on assignValids value <%s>\n", value.c_str() );
            fflush ( stdout ); //TODO
        }
    }
}
bool mibclass::parseline ( char * line )
{
    bool retval = false;
    //#physical channel
    const char * ccline = ( const char * ) line; // make compiler happy

    parse10params ( line ); // assumes no spaces inside params, assumes param<whitespace>param<whitespace>param...

    if ( strncmp ( ccline,"MY_SPACECRAFT_ID",strlen ( "MY_SPACECRAFT_ID" ) ) == 0 ) // my personal spacecraft id - if a mcid has a different spacecraft id than MY_SPACECRAFT_ID, the source/destination bit will be set to 1 (destination)
    {
        global_MY_SPACECRAFT_ID = kintval ( param[1] );
    }
    else if ( strncmp ( ccline,"PHYSICAL_CHANNEL_",strlen ( "PHYSICAL_CHANNEL_" ) ) == 0 ) // physical channel mib value
    {
        //
        // physical channel info - physicalChannel is physchan
        //
        // param[1] = physical channel
        // (?) param[2] is value
        //
        String & physchan = param[1]; // physical channel is the 1st parameter
        String & value = param[2]; // value is the 2nd parameter
        //
        if ( strstr ( ccline,"PHYSICAL_CHANNEL_Name" ) != NULL )
        {
            // no need to verify physchan - a new one will be made or overwritten
            pcmap[physchan] = new kphysicalChannel ( physchan.c_str() ); // make one if it doesn't exist, replace it if it does
        }
        else if ( strstr ( ccline,"PHYSICAL_CHANNEL_IP_Address" ) != NULL )
        {
            if ( verifyPhysChan ( physchan ) )
            {
                strncpy ( pcmap[physchan]->m_multicast_addr,value.c_str(),sizeof ( pcmap[physchan]->m_multicast_addr ) );
            }
        }
        else if ( strstr ( ccline,"PHYSICAL_CHANNEL_TX_Port_RX_Port" ) != NULL )
        {
            if ( verifyPhysChan ( physchan ) )
            {
                pcmap[physchan]->m_TXport = kintval ( value );
                pcmap[physchan]->m_rxport = kintval ( param[3] );
                klmprintf ( "physchan %s txing on port %d rxing on port %d\n",pcmap[physchan]->m_Name.c_str(),pcmap[physchan]->m_TXport,pcmap[physchan]->m_rxport); fflush ( stdout );
            }
        }
        else if ( strstr ( ccline,"PHYSICAL_CHANNEL_Transfer_Frame_Type" ) != NULL )
        {
            if ( verifyPhysChan ( physchan ) )
            {
                if ( strlen(klmglobalFrameType) != 0 ) // passed in from command line
                {
                    value.clear();
                    value.append(klmglobalFrameType);
                }
                pcmap[physchan]->m_pc_Transfer_Frame_Type = enumFixedVariable ( value );
            }
        }
        else if ( strstr ( ccline,"PHYSICAL_CHANNEL_Transfer_Frame_Length" ) != NULL )
        {
            if ( verifyPhysChan ( physchan ) )
            {
                pcmap[physchan]->m_pc_Transfer_Frame_Length = kintval ( value );
                if ( klmglobalFrameSize != -1 ) // if a value has been passed in by a command line argument
                {
                    pcmap[physchan]->m_pc_Transfer_Frame_Length = klmglobalFrameSize; // overwrite with global command line value
                }
            }
        }
        else if ( strstr ( ccline,"PHYSICAL_CHANNEL_Transfer_Frame_Version_Number" ) != NULL )
        {
            if ( verifyPhysChan ( physchan ) )
            {
                pcmap[physchan]->m_Transfer_Frame_Version_Number = kintval ( value );
            }
        }
        else if ( strstr ( ccline,"PHYSICAL_CHANNEL_MC_Multiplexing_Scheme" ) != NULL )
        {
            if ( verifyPhysChan ( physchan ) )
            {
                pcmap[physchan]->m_MC_Multiplexing_Scheme = kintval ( value );
            }
        }
        else if ( strstr ( ccline,"PHYSICAL_CHANNEL_Presence_of_Isochronous_Insert_Zone" ) != NULL )
        {
            if ( verifyPhysChan ( physchan ) )
            {
                if ( pcmap[physchan]->m_pc_Transfer_Frame_Type == eVariable && enumPresentAbsent ( value ) == ePresent )
                {
                    klmprintf("insert zone only legal on fixed frame types. exiting. %s\n",ccline);fflush(stdout);
                    exit(2);
                }
                else
                {
                    pcmap[physchan]->m_Presence_of_Isochronous_Insert_Zone = enumPresentAbsent ( value );
                }
            }
        }
        else if ( strstr ( ccline,"PHYSICAL_CHANNEL_Isochronous_Insert_Zone_Length" ) != NULL )
        {
            if ( verifyPhysChan ( physchan ) )
            {
                pcmap[physchan]->m_Isochronous_Insert_Zone_Length = kintval ( value ); // may be trumped to zero in readMibConfig if m_Presence_of_Isochronous_Insert_Zone = eAbsent or if m_pc_Transfer_Frame_Type == eVariable
            }
        }
        else if ( strstr ( ccline,"PHYSICAL_CHANNEL_Presence_of_Frame_Error_Control" ) != NULL )
        {
            if ( verifyPhysChan ( physchan ) )
            {
                pcmap[physchan]->m_Presence_of_Frame_Error_Control = enumPresentAbsent ( value );
            }
        }
        else if ( strstr ( ccline,"PHYSICAL_CHANNEL_Frame_Error_Control_Length" ) != NULL )
        {
            if ( verifyPhysChan ( physchan ) )
            {
                if ( pcmap[physchan]->m_Presence_of_Frame_Error_Control != ePresent )
                {
                    pcmap[physchan]->m_Frame_Error_Control_Length = 0;
                }
                else
                {
                    pcmap[physchan]->m_Frame_Error_Control_Length = kintval ( value );
                }
            }
        }
        else if ( strstr ( ccline,"PHYSICAL_CHANNEL_Generate_OID_Frame" ) != NULL )
        {
            if ( verifyPhysChan ( physchan ) )
            {
                pcmap[physchan]->m_pchan_Generate_OID_Frame = enumTrueFalse ( value );
            }
        }
        else if ( strstr ( ccline,"PHYSICAL_CHANNEL_Maximum_Number_of_Transfer_Frames_Given_to_the_Coding_And_Sync_Sublayer_as_a_Single_Data_Unit" ) != NULL )
        {
            if ( verifyPhysChan ( physchan ) )
            {
                pcmap[physchan]->m_Maximum_Number_of_Transfer_Frames_Given_to_the_Coding_And_Sync_Sublayer_as_a_Single_Data_Unit = kintval ( value );
            }
        }
        else if ( strstr ( ccline,"PHYSICAL_CHANNEL_Maximum_Value_of_the_Repetitions_Parameter_to_the_Coding_And_Synchronization_Sublayer" ) != NULL )
        {
            if ( verifyPhysChan ( physchan ) )
            {
                pcmap[physchan]->m_PhyschanMaxRepetitionsToCodingAndSyncSublayer = kintval ( value );
            }
        }
        else if ( strstr ( ccline,"PHYSICAL_CHANNEL_OID_Frame_Content" ) != NULL )
        {
            if ( verifyPhysChan ( physchan ) )
            {
                pcmap[physchan]->putOIDframeData( (unsigned char *) value.c_str());
            }
        }
    }
    //
    // master channel
    //
    else if ( strncmp ( ccline,"MASTER_CHANNEL_",strlen ( "MASTER_CHANNEL_" ) ) == 0 ) // master channel mib value
    {
        //
        // param[1] = is the  physical channel
        // kintval(param[2]) is master channel
        // (?) param[3] is value
        //
        String & physchan = param[1];
        int mc_id = kintval ( param[2] ); // get the value of the ID
        String & value = param[3];
        //
        //
        // VC&MC FRAME SERVICE PARAMETERS - PChan MCID VCID MAPID seqCtrlFrameCounterLen expFrameCounterLen delay-in-ms-between-releases-of-frames-from-the-same-vcid-timer
        //
        //

        if ( strstr ( ccline,"MASTER_CHANNEL_MC_ID" ) != NULL ||
                strstr ( ccline,"MASTER_CHANNEL_FRAME_SERVICE" ) != NULL
           ) // NOT IN march 21, 2016 spec yet in MC_ID managed parameters
        {
            if ( verifyPhysChan ( physchan ) ) // good physchan to add new masterChannel object onto
            {
                if ( mc_id >=0 && mc_id < MAX_MASTER_CHANNEL_IDS ) // verify number value before you make the object
                {
                    kphysicalChannel *lpcptr = pcmap[physchan];
                    lpcptr->m_MCmap[mc_id] = new kmasterChannel ( mc_id , pcmap[physchan]); // make one if it doesn't exist, replace it if it does
                    //
                    // if frame service mcid, add vcid and map objects
                    //
                    if ( strstr ( ccline,"MASTER_CHANNEL_FRAME_SERVICE" ) != NULL ) // this is a master channel frame service MCID
                    {
                        lpcptr->m_MCmap[mc_id]->setMcFrameService ( true ); // this IS a mc frame service MCID (constructor defaults to setting this to false

                        // param 3 vcid
                        int lvcid = atoi ( value.c_str() );
                        // param 4 mapid
                        int lmapid = atoi ( param[4].c_str() );
                        // param 5 seqctrl frame counter lengths
                        int lseqCtrlFrameCounterLen = atoi ( param[5].c_str() );
                        // param 6 expedited frame counter lengths
                        int lexpeditedFrameCounterLen = atoi ( param[6].c_str() );
                        kvcid *lvcidptr;
                        lpcptr->m_MCmap[mc_id]->m_vcidmap[lvcid] = new kvcid ( pcmap[physchan], pcmap[physchan]->m_MCmap[mc_id], lvcid ); // make one if it doesn't exist, replace it if it does
                        lvcidptr = lpcptr->m_MCmap[mc_id]->m_vcidmap[lvcid]; // assign abbreviated ptr
                        // trickle-down frame length
                        lvcidptr->m_vcid_Maximum_Transfer_Frame_Length = lpcptr->m_pc_Transfer_Frame_Length; // assure frame size fits inside physical channel constraints

                        // assign vcid timer
                        // param 7 milliseconds between frames of this vcid
                        lvcidptr->m_Maximum_delay_in_milliseconds_between_releases_of_frames_of_the_same_VC = atoi(param[7].c_str());
                        if ( atoi(param[7].c_str()) == 0 )
                        {
                            lvcidptr->m_timedVcidReleasesFlag = false;
                        }
                        else
                        {
                            lvcidptr->m_timedVcidReleasesFlag = true;
                        }
                        lvcidptr->m_VcidFrameService = true;
                        lvcidptr->m_vcSeqCtrlCountOctets = lseqCtrlFrameCounterLen;
                        lvcidptr->m_vcExpIntCountOctets = lexpeditedFrameCounterLen;
                        lvcidptr->m_mapmap[lmapid] = new kmapid ( pcmap[physchan], mc_id, lvcid, lmapid , pcmap[physchan]->m_MCmap[mc_id]->m_vcidmap[lvcid] ); // make one if it doesn't exist, replace it if it does
                        // mapid timers are reset in constructor
                        // set the spacecraftID for the map from the mcid
                        lvcidptr->m_mapmap[lmapid]->m_map_Spacecraft_ID = mc_id & 0xffff;
                    }
                }
                else
                {
                    klmprintf ( "error - illegal MC_ID value\n" );
                    fflush ( stdout ); // TODO // all subsequent parameters are doomed to be dropped
                }
            }
            else
            {
                klmprintf ( "error - illegal MC_ID physchan\n" );
                fflush ( stdout ); // TODO // all subsequent parameters are doomed to be dropped
            }
        }
        else if ( strstr ( ccline,"MASTER_CHANNEL_Transfer_Frame_Type" ) != NULL )
        {
            //
            // from the 8/9/2016 email from ed greenberg - this parameter is trumped by the physical channel frame type if fixed length
            //
            if ( verify_MC_ID ( physchan,mc_id ) ) 
            {
                if ( strlen(klmglobalFrameType) != 0 ) // passed in from command line
                {
                    value.clear();
                    value.append(klmglobalFrameType);
                }
                pcmap[physchan]->m_MCmap[mc_id]->m_MC_Transfer_Frame_Type = enumFixedVariable ( value );
            }
        }
        else if ( strstr ( ccline,"MASTER_CHANNEL_Spacecraft_ID" ) != NULL )
        {
            if ( verify_MC_ID ( physchan,mc_id ) )
            {
                //
                // verify that the spacecraft id given matches the one in the mcid field already
                //
                if ( ( mc_id & 0xffff) != kintval(value) )
                {
                    klmprintf ( "error - MC_ID spacecraft id %d does not match with MC_ID parameter %d in line:\n%s\nexiting. \n",kintval(value), mc_id ,ccline);
                    fflush ( stdout ); // TODO // all subsequent parameters are doomed to be dropped
                    exit(1);
                }	
                else // it MATCHES
                {
                    pcmap[physchan]->m_MCmap[mc_id]->m_MC_SpacecraftId = kintval ( value );
                }	
            }
        }
        else if ( strstr ( ccline,"MASTER_CHANNEL_VCIDs" ) != NULL )
        {
            if ( verify_MC_ID ( physchan,mc_id ) )
            {
                kassignValids ( value,MAX_VCIDS,pcmap[physchan]->m_MCmap[mc_id]->m_mc_VCIDs );
            }
        }
        else if ( strstr ( ccline,"MASTER_CHANNEL_VC_Multiplexing_Scheme" ) != NULL )
        {
            if ( verify_MC_ID ( physchan,mc_id ) )
            {
                pcmap[physchan]->m_MCmap[mc_id]->m_MC_VC_Multiplexing_Scheme = kintval ( value );
            }
        }
        else if ( strstr ( ccline,"MASTER_CHANNEL_Number_of_Times_To_Release_OCF_After_Delivery" ) != NULL )
        {
            if ( verify_MC_ID ( physchan,mc_id ) )
            {
                pcmap[physchan]->m_MCmap[mc_id]->m_timesToReleaseOcfAfterDelivery = kintval ( value );
            }
        }
    }
    //
    // virtual channel
    //
    else if ( strncmp ( ccline,"VIRTUAL_CHANNEL_",strlen ( "VIRTUAL_CHANNEL_" ) ) == 0  || strstr ( ccline, "COP_SERVICE_SAP") != NULL ) // do the same verification/preprocessing on these two possibilities
    {
        //
        // param[1] = is the  physical channel
        // kintval(param[2]) is master channel
        // kintval(param[3]) is virtual channel
        // (?) param[4] is value
        //
        String & physchan = param[1]; //  physical channel is 1st param
        int l_MC_id = kintval ( param[2] ); // master channel is 2nd param
        int lvcid = kintval ( param[3] ); // vcid is 3rd param
        String & value = param[4];    // value is 4th param
        //
        // virtual channel info - mc_id is physchan
        //
        // either line is for either a vcid delcaration or vcid frame service declaration since 1 vcid can't be both.
        //  both vc_vcid and vc_frame_service create a new vcid object with this vcid
        if ( strstr ( ccline,"VIRTUAL_CHANNEL_MAP_IDs" ) != NULL ||
                strstr ( ccline, "COP_SERVICE_SAP") != NULL || // cop service is like frame serivce - one self-contained declaration
                strstr ( ccline,"VIRTUAL_CHANNEL_FRAME_SERVICE" ) != NULL
           )
        {
            if ( lvcid >= 0 && lvcid < MAX_VCIDS ) // verify number value before you create kvcid object
            {
                // verify mc_id and current physical channel
                if ( verify_MC_ID ( physchan,l_MC_id ) ) // verify physical channel and master channel before adding a vcid object
                {
                    kphysicalChannel *lpcptr = pcmap[physchan];
                    // make sure it doesn't already exist
                    if ( lpcptr->m_MCmap[l_MC_id]->m_vcidmap.find ( lvcid ) == lpcptr->m_MCmap[l_MC_id]->m_vcidmap.end() )
                    {
                        lpcptr->m_MCmap[l_MC_id]->m_vcidmap[lvcid] = new kvcid (pcmap[physchan], pcmap[physchan]->m_MCmap[l_MC_id], lvcid ); // make one if it doesn't exist, replace it if it does
                        kvcid *lvcidptr = lpcptr->m_MCmap[l_MC_id]->m_vcidmap[lvcid];
                        if ( strstr ( ccline,"VIRTUAL_CHANNEL_FRAME_SERVICE" ) != NULL ) // this is a vcid frame service delcaration - go on and do some other things
                        {
                            lvcidptr->m_VcidFrameService = true;
                            // set max frame length
                            lvcidptr->m_vcid_Maximum_Transfer_Frame_Length = lpcptr->m_pc_Transfer_Frame_Length; // propagate max frame length down from master channel frame length
                            // param 4 = mapid
                            int lmapid = atoi ( param[4].c_str() ); // get mapid
                            lvcidptr->m_mapmap[lmapid] = new kmapid ( pcmap[physchan], l_MC_id, lvcid, lmapid ,lpcptr->m_MCmap[l_MC_id]->m_vcidmap[lvcid]); // add the dummy mapid object (for consistent searching)
                            // and mapid spacecraft id
                            lvcidptr->m_mapmap[lmapid]->m_map_Spacecraft_ID = l_MC_id & 0xffff;
                            // param 5 = vcid sequence controlled frame counter length
                            lvcidptr->m_vcSeqCtrlCountOctets = atoi ( param[5].c_str() ); // how many octets for this vcid (0-7)
                            // param 6 = vcid expedited frame counter length
                            lvcidptr->m_vcExpIntCountOctets = atoi ( param[6].c_str() ); // how many octets for this vcid (0-7)
                            // param 7 = vcid timeout and tfdf length
                            lvcidptr->m_Maximum_delay_in_milliseconds_between_releases_of_frames_of_the_same_VC = atoi(param[7].c_str());
                        }
                        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_MAP_IDs" ) != NULL )
                        {
                            if ( lvcid == 63 ) // special case for VCID 63 - need automatic mapid 0 under it
                            {
                                // FORCE mapid 0 under it
                                String defaultZeroMapid = "0";
                                kassignValids ( defaultZeroMapid,MAX_MAP_IDS,pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_vc_MAP_IDs );
                                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_mapmap[0] = new kmapid ( pcmap[physchan], l_MC_id, lvcid, 0, pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid] ); // make one if it doesn't exist, replace it if it does
                                // assign map spacecraft id based on master channel
                                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_mapmap[0]->m_map_Spacecraft_ID = l_MC_id & 0xffff; 
                                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_mapmap[0]->m_txBypassFlag = eExpedited; // set OID frame to be expedited (vc frame counter length is set by "expedited" parameter
                            }
                            else if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
                            {
                                kassignValids ( value,MAX_MAP_IDS,pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_vc_MAP_IDs );

                                for ( int mp = 0; mp < MAX_MAP_IDS; mp ++ )
                                {
                                    if ( pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_vc_MAP_IDs[mp] ) // if this one is valid
                                    {
                                        // make a mapid
                                        pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_mapmap[mp] = new kmapid ( pcmap[physchan], l_MC_id, lvcid, mp, pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid] ); // make one if it doesn't exist, replace it if it does
                                        pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_mapmap[mp]->m_map_Spacecraft_ID = l_MC_id & 0xffff;  // assign spacecraft id from VIRTUAL_CHANNEL_MAP_IDs parameter
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        klmprintf ( "error - vcid %d duplicate VIRTUAL_CHANNEL_VCID definition\n",lvcid );
                        fflush ( stdout );
                    }
                }
                else
                {
                    klmprintf ( "error - unverified PC/MC_ID %s %d for new vcid %d \n",physchan.c_str(),l_MC_id,lvcid );
                    fflush ( stdout ); // TODO // all subsequent parameters are doomed to be dropped
                }
            }
            else
            {
                klmprintf ( "error - illegal VCID value %d \n",lvcid );
                fflush ( stdout ); // TODO // all subsequent parameters are doomed to be dropped
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_Transfer_Frame_Type" ) != NULL )
        {
            //
            // from the 8/9/2016 email from ed greenberg - this parameter is trumped by the physical channel frame type if fixed length (trumping is done at the end of readMibConfig)
            //
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                if ( strlen(klmglobalFrameType) != 0 ) // passed in from command line
                {
                    value.clear();
                    value.append(klmglobalFrameType);
                }
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_vcid_Transfer_Frame_Type = enumFixedVariable ( value ) ;
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_VCID" ) != NULL )
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_vcid_VCID = kintval(value);
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_VC_Count_Length_for_Sequence_Control" ) != NULL )
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->setVcSeqCtrlOctets ( kintval ( value ) );
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_VC_Count_Length_for_Expedited_Integer" ) != NULL )
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->setVcExpIntOctets ( kintval ( value ) );
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_COP_in_Effect" ) != NULL )
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_COP_in_Effect = kintval ( value );
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_CLCW_Version_Number" ) != NULL )
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_CLCW_Version_Number = kintval ( value );
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_CLCW_Reporting_Rate" ) != NULL )
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_CLCW_Reporting_Rate = value; // passed as a string
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_MAP_Multiplexing_Scheme" ) != NULL )
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_vc_MAP_Multiplexing_Scheme = kintval ( value );
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_Truncated_Frame_Total_Length" ) != NULL )
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                int trunclen = kintval (value ) > MAX_TRUNCATED_FRAME_TOTAL_LENGTH ? MAX_TRUNCATED_FRAME_TOTAL_LENGTH : kintval (value );
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_truncatedFrameTotalLength = trunclen;
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_Inclusion_of_OCF_Allow_Variable_Length_Frames" ) != NULL )
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_allowVariableFrameInclusionOfOcf = enumTrueFalse ( value );
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_Inclusion_of_OCF_Required_Fixed_Length_Frames" ) != NULL )
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_vcRequireFixedFrameInclusionOfOcf = enumTrueFalse ( value );
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_service_data_on_the_Sequence_Controlled_Service" ) != NULL )
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                int lreps = kintval ( value );
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_RepetitionsValueUNLIMITEDbyPhyschanValue = lreps; // save unlimited value for expedited frames
                if ( pcmap[physchan]->m_PhyschanMaxRepetitionsToCodingAndSyncSublayer < lreps ) // if physchan value is smaller overwrite seqControlled value
                {
                    pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_service_data_on_the_Sequence_Controlled_Service = pcmap[physchan]->m_PhyschanMaxRepetitionsToCodingAndSyncSublayer;
                }
                else
                {
                    pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_service_data_on_the_Sequence_Controlled_Service = lreps;
                }
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_COP_control_commands" ) != NULL )
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                int lreps = kintval ( value );
                if ( pcmap[physchan]->m_PhyschanMaxRepetitionsToCodingAndSyncSublayer < lreps ) // if physchan value is smaller overwrite COP repetitions value
                {
                    pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_COP_control_commands = pcmap[physchan]->m_PhyschanMaxRepetitionsToCodingAndSyncSublayer;
                }
                else
                {
                    pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_COP_control_commands = lreps;
                }
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_Maximum_delay_in_milliseconds_between_releases_of_frames_of_the_same_VC" ) != NULL )
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_Maximum_delay_in_milliseconds_between_releases_of_frames_of_the_same_VC = kintval ( value );
                if ( pcmap[physchan]->m_pchan_Generate_OID_Frame == eFalse ) // this trumps everything else
                {
                    pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_timedVcidReleasesFlag = false; // NO oid frames if pc frame type is not fixed
                }
                else if ( pcmap[physchan]->m_pc_Transfer_Frame_Type != eFixed )
                {
                    pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_timedVcidReleasesFlag = false; // NO oid frames if pc frame type is not fixed
                }
                else if ( kintval (value) == 0)
                {
                    pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_timedVcidReleasesFlag = false; // no oid frames if timer is set to 0
                }
                else
                {
                    pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_timedVcidReleasesFlag = true; // if pc frame type is fixed AND timer is not set to 0 then tx an oid frame
                }
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_Presence_of_Space_Data_Link_Security_Header" ) != NULL ) // security header
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_PresenceOfSpaceDataLinkSecurityHeader = enumPresentAbsent( value );
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_Presence_of_Space_Data_Link_Security_Trailer" ) != NULL ) // security trailer
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_PresenceOfSpaceDataLinkSecurityTrailer = enumPresentAbsent( value );
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_Length_of_Space_Data_Link_Security_Header" ) != NULL ) // security header
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_LengthOfSpaceDataLinkSecurityHeader = kintval( value );
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_Length_of_Space_Data_Link_Security_Trailer" ) != NULL ) // security header
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_LengthOfSpaceDataLinkSecurityTrailer = kintval( value );
            }
        }
        else if ( strstr ( ccline,"VIRTUAL_CHANNEL_Maximum_Ms_Delay_to_Release_TFDF_Once_Started" ) != NULL )
        {
            if ( verifyVCID ( physchan,l_MC_id,lvcid ) )
            {
                pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_vc_maxMsDelayToReleaseTfdfOnceStarted = kintval ( value );
            }
        }
    }

    //
    // map_id
    //

    else if ( strncmp ( ccline,"MAP_CHANNEL_",strlen ( "MAP_CHANNEL_" ) ) == 0 )
    {
        //
        // param[1] = is the  physical channel
        // kintval(param[2]) is master channel
        // kintval(param[3]) is virtual channel
        // kintval(param[4]) is map id
        // kintval(param[5]) is value
        //
        String & physchan = param[1]; //  physical channel is 1st param
        int l_MC_id = kintval ( param[2] ); // master channel is 2nd param
        int lvcid = kintval ( param[3] ); // vcid is 3rd param
        int lmapid = kintval ( param[4] );  // map_id is 4th param
        String & value = param[5];    // value is 5th param

        if ( strstr ( ccline,"MAP_CHANNEL_MAP_ID" ) != NULL )
        {
            if ( verifyMAP_ID ( physchan,l_MC_id,lvcid,lmapid ) )
            {
                if ( kintval ( value ) != pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_mapmap[lmapid]->m_map_MAPID)  // mapid should already exist because of vcid VIRTUAL_CHANNEL_MAP_IDs line
                {
                    klmprintf("error in <%s>: MAP_CHANNEL_MAP_ID param for map id. is %d should be %d\n",ccline, kintval(value),pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_mapmap[lmapid]->m_map_MAPID);
                    exit(1);
                }
            }
        }
        /* values "MAP_CHANNEL_Minimum_TFDF_Length" and "MAP_CHANNEL_Maximum_TFDF_Length" to be removed 7/26/2017 email from greg is calculated now at end of readMibConfig
           else if ( strstr ( ccline,"MAP_CHANNEL_Minimum_TFDF_Length" ) != NULL )
           {
           if ( verifyMAP_ID ( physchan,l_MC_id,lvcid,lmapid ) )
           {
           pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_mapmap[lmapid]->m_map_MinimumTfdfLength = kintval ( value );
           }
           }
           else if ( strstr ( ccline,"MAP_CHANNEL_Maximum_TFDF_Length" ) != NULL )
           {
           if ( verifyMAP_ID ( physchan,l_MC_id,lvcid,lmapid ) )
           {
        // TODO - have pc,mc,vc frame channel affect max
        pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_mapmap[lmapid]->m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR = kintval ( value );
        }
        }
        */
           else if ( strstr ( ccline,"MAP_CHANNEL_OctetStream_DeliverLength" ) != NULL )
           {
               if ( verifyMAP_ID ( physchan,l_MC_id,lvcid,lmapid ) )
               {
                   pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_mapmap[lmapid]->m_map_octetStreamDeliverLength = kintval ( value );
               }
           }
           else if ( strstr ( ccline,"MAP_CHANNEL_OctetStream_RequestLength" ) != NULL )
           {
               if ( verifyMAP_ID ( physchan,l_MC_id,lvcid,lmapid ) )
               {
                   pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_mapmap[lmapid]->m_map_octetStreamRequestLength = kintval ( value );
               }
           }
           else if ( strstr ( ccline,"MAP_CHANNEL_Service_Data_Unit_Type" ) != NULL )
           {
               if ( verifyMAP_ID ( physchan,l_MC_id,lvcid,lmapid ) )
               {
                   pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_mapmap[lmapid]->m_map_ServiceDataUnitType = enumServiceData ( value );
                   if ( enumServiceData ( value ) == eOCTET_STREAM )
                   {
                       if (pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_mapmap[lmapid]->m_map_octetStreamDeliverLength == 0
                               ||
                               pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_mapmap[lmapid]->m_map_octetStreamRequestLength == 0
                          ) // octet stream svc type with no specified octet stream request&deliver length
                       {
                           klmprintf("error in <%s>: nonzero MAP_CHANNEL_OctetStream_DeliverLength AND nonzero MAP_CHANNEL_OctetStream_RequestLength *MUST BE* specified before MAP_CHANNEL_Service_Data_Unit_Type parameter if type is octet_stream. exiting.\n",ccline);fflush(stdout);
                           exit(1);
                       }
                       else if ( pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_vcid_Transfer_Frame_Type == eFixed )
                       {
                           klmprintf("octet_stream specified in MAPID with FIXED VCID frame length. illegal. exiting.%s\n",ccline);fflush(stdout);
                           exit(1);
                       }
                   }
               }
           }
           else if ( strstr ( ccline,"MAP_CHANNEL_USLP_Protocol_ID_Supported" ) != NULL )
           {
               if ( verifyMAP_ID ( physchan,l_MC_id,lvcid,lmapid ) )
               {
                   kmapid *lpmapid = pcmap[physchan]->m_MCmap[l_MC_id]->m_vcidmap[lvcid]->m_mapmap[lmapid];
                   int lpid = kintval ( value ) ;
                   if ( lpid < 32 )
                   {
                       lpmapid->m_map_UslpProtocolIdSupported = kintval ( value );  //oct spec doesn't use extended protocol octet so protocol ID can be from 0 to 31
                   }
                   else
                   {
                       klmprintf("error in line <%s> - protocol id must be between 0 and 31\n",ccline);fflush(stdout);
                       exit(2);
                   }
                   /*
                      oct spec doesn't use extended protocol octet so protocol ID can be from 0 to 31
                      int lpid = kintval ( value );
                      if ( lpid < 31 ) // doesn't need extended protocol id
                      {
                      lpmapid->m_map_UslpProtocolIdSupported = lpid;
                      }
                      else // NEEDS extended protocol id // TODO eliminate this since there's no extended protocol id anymore as of oct 2016
                      {
                      lpmapid->m_map_UslpProtocolIdSupported = 31;
                      }
                      */
                   // prot id assigned to permap header in readMibConfig after everything is through reading
               }
           }
    }
    //
    // packet info
    //
    else if ( strncmp ( ccline,"PACKET_",strlen ( "PACKET_" ) ) == 0 ) // make sure identifier STARTS with "PACKET_" as opposed to finding-it-anywhere-in-the-line
    {
        //
        // packet info
        //
        if ( strstr ( ccline,"PACKET_Valid_Packet_Version_Numbers" ) != NULL )
        {
            kassignValids ( param[1], MAX_PACKET_VERSION_NUMBERS, packetInfoMib.m_Valid_Packet_Version_Numbers );
            // assign minimum valid packet number and TOTAL valid packet numbers
            packetInfoMib.m_numberOfValidPvns = 0; // start count off at 0
            for ( int q = 0 ; q < MAX_PACKET_VERSION_NUMBERS ; q ++ )
            {
                if (packetInfoMib.m_Valid_Packet_Version_Numbers[q])
                {
                    packetInfoMib.m_numberOfValidPvns++; // bump total count
                    if (packetInfoMib.m_minimumValidPvn < 0 ) // if you don't already have a minimum
                    {
                        packetInfoMib.m_minimumValidPvn = q; // save this one
                    } 
                }
            }
            if (packetInfoMib.m_minimumValidPvn < 0 )
            {
                klmprintf("error - no PACKET_Valid_Packet_Version_Numbers given. must have at least one value from 0-7\n");fflush(stdout);// TODO handle error
            }
            klmprintf("Valid PVNs - %d minimum Valid Pvn = %d\n",packetInfoMib.m_numberOfValidPvns,packetInfoMib.m_minimumValidPvn);fflush(stdout);
            packetInfoMib.constructOrderedValidPvns();
        }
        else if ( strstr ( ccline,"PACKET_Maximum_Packet_Length" ) != NULL )
        {
            packetInfoMib.m_Maximum_Packet_Length = kintval ( param[1] );
        }
        else if ( strstr ( ccline,"PACKET_Require_Incomplete_Packet_Delivery_To_User_At_Receiving_End " ) != NULL )
        {
            packetInfoMib.m_Require_Incomplete_Packet_Delivery_To_User_At_Receiving_End = enumTrueFalse ( param[1] );
        }
    }
    else if ( strstr ( ccline,"MAPA_Require_Incomplete_MAPA_Delivery_To_User_At_Receiving_End " ) != NULL )
    {
        global_Require_Incomplete_MAPA_Delivery_To_User_At_Receiving_End = enumTrueFalse ( param[1] );
    }
    //
    //
    // matched nothing
    //
    //
    else
    {
        klmprintf ( "no match for mib param line <%s>\n",line );
        fflush ( stdout );
        retval = false;
    }
    return retval;
}
void mibclass::dumpPacketMib ( void )
{
    klmprintf ( "Packet Mib:\n" );
    klmprintf ( "	Valid Packet Version Numbers: " );
    for ( int i = 0 ; i < MAX_PACKET_VERSION_NUMBERS ; i ++ )
    {
        if ( packetInfoMib.m_Valid_Packet_Version_Numbers[i] ) // bool flagged as valid
        {
            klmprintf ( "%d ",i );
        }
    }
    klmprintf ( "\n" );
    klmprintf ( "	Maximum Packet Length: %d\n",packetInfoMib.m_Maximum_Packet_Length );
    klmprintf ( "	Require Incomplete Packet Delivery To User at Receiving End: %s\n",strTrueFalse ( packetInfoMib.m_Require_Incomplete_Packet_Delivery_To_User_At_Receiving_End ) );
    klmprintf ( "	Require Incomplete MAPA Delivery To User at Receiving End: %s\n",strTrueFalse ( global_Require_Incomplete_MAPA_Delivery_To_User_At_Receiving_End ) );
    fflush ( stdout );
}
void mibclass::dumpMapMap ( std::map<int,kmapid *> & mapmap )
{
    std::map<int, kmapid *>::iterator it;
    for ( it = mapmap.begin(); it != mapmap.end(); it++ )
    {
        klmprintf ( "			mapid %d:\n", it->second->m_map_MAPID );
        klmprintf ( "				mapVCID: %d\n", it->second->m_map_VCID );
        klmprintf ( "				mapSpacecraft ID: %d\n", it->second->m_map_Spacecraft_ID );
        klmprintf ( "			  map MAP ID: %d\n",it->second->m_map_MAPID ); // bool flagged as valid
        klmprintf ( "				Maximum TFDF Length_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR: %d\n", it->second->m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR );
        klmprintf ( "				Service Data Unit Type: %s\n", strServiceData ( it->second->m_map_ServiceDataUnitType ) );
        klmprintf ( "				USLP Protocol ID Supported: %d\n", it->second->m_map_UslpProtocolIdSupported );
        klmprintf ( "				MAP Max ms delay to release tfdf once started: %d\n", it->second->m_map_maxMsDelayToReleaseTfdfOnceStarted_fromvc );
    }
    fflush ( stdout );
}
void mibclass::dumpVcidMap ( std::map<int,kvcid *> & vcidmap )
{
    std::map<int, kvcid *>::iterator it;
    for ( it = vcidmap.begin(); it != vcidmap.end(); it++ )
    {
        klmprintf ( "		vcid %d:\n", it->second->m_VCID );
        klmprintf ( "			Vc Frame Service? : %s\n",strTrueFalse(it->second->m_VcidFrameService) );
        klmprintf ( "			Vc MAP IDs: " );
        for ( int i = 0 ; i < MAX_MAP_IDS ; i ++ )
        {
            if ( it->second->m_vc_MAP_IDs[i] ) // bool flagged as valid
            {
                klmprintf ( "%d ",i );
            }
        }
        klmprintf ( "\n" );
        klmprintf ( "			Txfr Frame Type: %s\n", strFixedVariable ( it->second->m_vcid_Transfer_Frame_Type ) );
        klmprintf ( "			Vc VCID: %d\n", it->second->m_vcid_VCID );
        klmprintf ( "			Vc Count Size for SequenceControl: %d\n",it->second->m_vcSeqCtrlCountOctets );
        klmprintf ( "			Vc Count Size for Expedited Integer: %d\n",it->second->m_vcExpIntCountOctets );
        klmprintf ( "			COP_in_Effect: %s\n",strTrueFalse ( it->second->m_COP_in_Effect ) );
        klmprintf ( "			CLCW_Version_Number: %d\n",it->second->m_CLCW_Version_Number );
        klmprintf ( "			CLCW_Reporting_Rate: %s\n",it->second->m_CLCW_Reporting_Rate.c_str() );
        klmprintf ( "			vc MAP_Multiplexing_Scheme: %d\n", it->second->m_vc_MAP_Multiplexing_Scheme );
        klmprintf ( "			Truncated Primary Transfer Frame Header Length: %d\n", it->second->m_truncatedFrameTotalLength );
        klmprintf ( "			Allow Variable Frame Inclusion of OCf: %s\n", strTrueFalse ( it->second->m_allowVariableFrameInclusionOfOcf ) );
        klmprintf ( "			Require Fixed Frame Inclusion of OCf: %s\n", strTrueFalse ( it->second->m_vcRequireFixedFrameInclusionOfOcf ) );
        klmprintf ( "			Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_service_data_on_the_Sequence_Controlled_Service: %d\n",it->second->m_Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_service_data_on_the_Sequence_Controlled_Service );
        klmprintf ( "			Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_COP_control_commands: %d\n",it->second->m_Value_for_the_Repetitions_parameter_to_the_Coding_And_Sync_Sublayer_when_transferring_frames_carrying_COP_control_commands );
        klmprintf ( "			Maximum_delay_in_milliseconds_between_releases_of_frames_of_the_same_VC: %d\n",it->second->m_Maximum_delay_in_milliseconds_between_releases_of_frames_of_the_same_VC );
        klmprintf ( "			ARE there timed vcid releases? %s\n",it->second->m_timedVcidReleasesFlag ? "true":"false" );
        klmprintf ( "			VC max ms delay to release tfdf once started: %d\n", it->second->m_vc_maxMsDelayToReleaseTfdfOnceStarted );
        klmprintf ( "			Presence of security header : %s\n",strPresentAbsent(it->second->m_PresenceOfSpaceDataLinkSecurityHeader ));
        klmprintf ( "			SecurityHeaderLen: %d\n",it->second->m_LengthOfSpaceDataLinkSecurityHeader);
        kprMutex.lock();printf ( "			SecurityHeaderData: ");seedata(it->second->m_spaceDataLinkSecurityHeader,it->second->m_LengthOfSpaceDataLinkSecurityHeader);printf("\n");kprMutex.unlock();
        klmprintf ( "			Presence of security trailer : %s\n",strPresentAbsent(it->second->m_PresenceOfSpaceDataLinkSecurityTrailer ));
        klmprintf ( "			SecurityTrailerLen: %d\n",it->second->m_LengthOfSpaceDataLinkSecurityTrailer);
        kprMutex.lock();printf ( "			SecurityTrailerData: ");seedata(it->second->m_spaceDataLinkSecurityTrailer,it->second->m_LengthOfSpaceDataLinkSecurityTrailer);printf("\n");kprMutex.unlock();
        dumpMapMap ( it->second->m_mapmap );
    }
    fflush ( stdout );
}
void mibclass::dumpMasterChannelMap ( std::map <int,kmasterChannel *> & mcmap )
{
    std::map<int, kmasterChannel *>::iterator it;
    for ( it = mcmap.begin(); it != mcmap.end(); it++ )
    {
        klmprintf ( "	mc_id %d:\n", it->second->m_MC_ID );
        klmprintf ( "		MC Frame Service? : %s\n", strTrueFalse ( it->second->m_mcFrameService ) );
        klmprintf ( "		mc_id Txfr Frame Type: %s\n", strFixedVariable ( it->second->m_MC_Transfer_Frame_Type ) );
        kprMutex.lock();printf ( "		  OCF data: ");seedata(it->second->m_ocfBuf,4);printf("\n");kprMutex.unlock();
        klmprintf ( "		  OCF length: %d\n",it->second->m_ocfLen);
        klmprintf ( "		Valid VCIDs: " );
        for ( int i = 0 ; i < MAX_VCIDS ; i ++ )
        {
            if ( it->second->m_mc_VCIDs[i] ) // bool flagged as valid
            {
                klmprintf ( "%d ",i );
            }
        }
        klmprintf ( "\n" );
        klmprintf ( "		Spacecraft ID: %d\n",it->second->m_MC_SpacecraftId );
        klmprintf ( "		VC Multiplexing Scheme: %d\n",it->second->m_MC_VC_Multiplexing_Scheme );
        klmprintf ( "\n" );
        dumpVcidMap ( it->second->m_vcidmap );
    }
    fflush ( stdout );
}
void mibclass::dumpPhysicalChannelMap ( void )
{
    std::map<String, kphysicalChannel *>::iterator it;
    for ( it = pcmap.begin(); it != pcmap.end(); it++ )
    {
        klmprintf ( "pc %s:\n", it->second->m_Name.c_str() );
        klmprintf ( "	Txfr Frame Type: %s\n", strFixedVariable ( it->second->m_pc_Transfer_Frame_Type ) );
        klmprintf ( "	Max Txfr Frame Len: %d\n",it->second->m_pc_Transfer_Frame_Length );
        klmprintf ( "	Txfr Frame Version: %d\n",it->second->m_Transfer_Frame_Version_Number );
        klmprintf ( "	Mc Mux Scheme: %d\n",it->second->m_MC_Multiplexing_Scheme );
        klmprintf ( "	Isoch IZ: %s\n", strPresentAbsent ( it->second->m_Presence_of_Isochronous_Insert_Zone ) );
        klmprintf ( "	Isoch IZ Len: %d\n", it->second->m_Isochronous_Insert_Zone_Length );
        klmprintf ( "	FEC: %s\n", strPresentAbsent ( it->second->m_Presence_of_Frame_Error_Control ) );
        klmprintf ( "	FEC Len: %d\n",it->second->m_Frame_Error_Control_Length );
        klmprintf ( "	PChan Generate OID Frame: %s\n",strTrueFalse ( it->second->m_pchan_Generate_OID_Frame ));
        klmprintf ( "	FasSdu: %d\n",it->second->m_Maximum_Number_of_Transfer_Frames_Given_to_the_Coding_And_Sync_Sublayer_as_a_Single_Data_Unit );
        klmprintf ( "	MVreps: %d\n",it->second->m_PhyschanMaxRepetitionsToCodingAndSyncSublayer );
        klmprintf ( "\n" );
        dumpMasterChannelMap ( it->second->m_MCmap );
    }
    fflush ( stdout );
}
void mibclass::dumpConfigs ( void )
{
    dumpPhysicalChannelMap();
    dumpPacketMib();
}
    bool mibclass::parseTransferFrameHeader 
(
 kphysicalChannel *lptrphyschan,
 unsigned char *fp, // pointer at octet 0 of the frame
 int rxframelen, // how big the calling function says the frame is
 int *version_id,
 int *spacecraftId,
 int *dest_src,
 int *vcid,
 int *mapid,
 int *endOfTransferFrameHeader,
 int *framelen,
 int *bypassFlag,
 int *protocolCommandControlFlag,
 int *ocfFlag,
 int *vcSeqCounterOctets,
 long long *vcSequenceCount,
 int *offsetOfFirstOctetPastVcCounters, // actual sequence count (can't be more octets than vcSeqCounterOctets)
 bool *isTruncatedFrame,  // flag
 bool *isOidFrame // flag
 )
{
    klmprintf("rxframelen %d\n",rxframelen);fflush(stdout);
    // 
    // version id
    // 
    Uic.i = 0;
    Uic.c[i_03lsbtomsb[0]] = fp[0]; // lsb
    *version_id = Uic.i >> 4;
    // kprMutex.lock();printf("pesult = vrsid %15d %15d ",*version_id, Uic.i);seedata(fp,20);printf("\n");fflush(stdout);kprMutex.unlock();
    klmprintf("pesult = vrsid %15d\n",*version_id);fflush(stdout);
    if ( *version_id != lptrphyschan->m_Transfer_Frame_Version_Number )
    {
        klmprintf("tfvn on this physchan should be %d - received %d - discarding. returning false\n",lptrphyschan->m_Transfer_Frame_Version_Number, *version_id);fflush(stdout);
        return(false);
    }

    // 
    // 
    // spacecraft id
    // 
    Uic.i = 0;
    Uic.c[i_03lsbtomsb[2]] = fp[0] & 0x0f; // put in next to msb
    Uic.c[i_03lsbtomsb[1]] = fp[1]; // put in next to lsb
    Uic.c[i_03lsbtomsb[0]] = fp[2]; // put in lsb
    *spacecraftId = Uic.i >> 4;
    //    kprMutex.lock();printf("pesult = sc id %15d %15d ",*spacecraftId, Uic.i);seedata(fp,20);printf("\n");fflush(stdout);kprMutex.unlock();
    klmprintf("pesult = sc id %15d\n",*spacecraftId);fflush(stdout);

    // 
    // source destination bit
    // 
    // no need to even use Uic - just look at the bit
    if ( fp[2] & 0x08 ) // point directly at the bit
    {
        *dest_src = 1;
    }	
    else	
    {	
        *dest_src = 0;
    }
    // kprMutex.lock();printf("pesult = srcdst%15d %15d ",*dest_src,Uic.i);seedata(fp,20);printf("\n");fflush(stdout);kprMutex.unlock();
    klmprintf("pesult = srcdst%15d \n",*dest_src);fflush(stdout);
    //
    // if dest_src == 1 then the scid should be the scid of the DESTINATION. if i'm parsing it it means i've received it and the dest should be MY scid.
    //
    if ( (*dest_src == 1) && *spacecraftId != global_MY_SPACECRAFT_ID )
    {
        klmprintf("destination bit set, but spacecraft ID %d does not match mine (%d), so this frame is not for me. discarding. returning false\n",*spacecraftId,global_MY_SPACECRAFT_ID);fflush(stdout);
        return(false);
    }

    // 
    // VCID (6 bits)
    // 
    Uic.i = 0;
    Uic.c[i_03lsbtomsb[1]] = fp[2] & 0x07; // put in next-to-lsb
    Uic.c[i_03lsbtomsb[0]] = fp[3] & 0xe0; // put in lsb
    *vcid = Uic.i >> 5;
    // kprMutex.lock();printf("pesult = VCID  %15d %15d ",*vcid, Uic.i);seedata(fp,20);printf("\n");fflush(stdout);kprMutex.unlock();
    klmprintf("pesult = VCID  %15d \n",*vcid);fflush(stdout);

    if ( *vcid == 63 )
    {
        *isOidFrame = true;
        *ocfFlag = 0; // NO OCF in OID frames from 4/14/2018 3:15pm email by greg kazz - NO ocfs in OID frames
    }
    else
    {
        *isOidFrame = false;
    }

    int lMCid = (*version_id * 65536) + *spacecraftId;
    int lvcid = *vcid; // depending on the setting in the VCID
    // 
    // MAPID (4 bits)
    // 
    Uic.i = 0;
    Uic.c[i_03lsbtomsb[0]] = fp[3] & 0x1e; // put in lsb
    *mapid = Uic.i >> 1;
    int lmapid = *mapid;
    // kprMutex.lock();printf("pesult = MAPID %15d %15d ",*mapid, Uic.i);seedata(fp,20);printf("\n");fflush(stdout);kprMutex.unlock();
    klmprintf("pesult = MAPID %15d \n",*mapid);fflush(stdout);

    bool goodMcidAndVcid = false;
    std::map <int,kmasterChannel *>::iterator lmcidIt = lptrphyschan->m_MCmap.find ( lMCid ); // see if MCid exists
    if ( lmcidIt != lptrphyschan->m_MCmap.end() ) // MC id found, check for vcid
    {
        std::map <int,kvcid *>::iterator lVcidIt = lmcidIt->second->m_vcidmap.find ( lvcid ); // if vcid object exists
        //
        // check vcid exists. 
        // MAKE EXCEPTION for vcid 63.
        //
        if ( lVcidIt != lmcidIt->second->m_vcidmap.end() || lvcid == 63 ) // found it - mcid and vcid are good
        {
            std::map <int,kmapid *>::iterator lMapid = lVcidIt->second->m_mapmap.find ( *mapid ); // if vcid object exists
            if ( lMapid != lVcidIt->second->m_mapmap.end() )
            {
                goodMcidAndVcid = true;
            }
            else
            {
                klmprintf("physchan %s MCID %d vcid %d received unmapped MAPid %d - dropping frame\n", lptrphyschan->m_Name.c_str(),lMCid, lvcid,*mapid );fflush(stdout);
            }
        }
        else
        {
            klmprintf("physchan %s MCID %d received unmapped Vcid %d - dropping frame\n", lptrphyschan->m_Name.c_str(),lMCid, lvcid );fflush(stdout);
        }
    }
    else
    {
        klmprintf("physchan %s received unmapped MCID %d - dropping frame\n", lptrphyschan->m_Name.c_str(),lMCid );fflush(stdout);
    }
    if ( goodMcidAndVcid != true ) // either mcid or vcid is bad
    {
        return false;
    }
    // 
    // end of transfer frame header flag
    // 
    // no need to even use Uic - just look at the bit
    if ( fp[3] & 0x01 ) // point directly at the bit
    {
        *endOfTransferFrameHeader = 1; // set flag
        *isTruncatedFrame = true; // set flag
        //
        // rules change - it's a truncated frame - nothing else to see here - just return "TRUNCATED" flag and calling routine will deliver rxbuf[4]... to truncated frame processor
        //
        return true;
    }	
    else	
    {	
        *endOfTransferFrameHeader = 0; // reset flag
        *isTruncatedFrame = false; // reset flag
    }
    // kprMutex.lock();printf("pesult = eotfh %15d %15d ",*endOfTransferFrameHeader, Uic.i);seedata(fp,20);printf("\n");fflush(stdout);kprMutex.unlock();
    klmprintf("pesult = eotfh %15d \n",*endOfTransferFrameHeader);fflush(stdout);

    // 
    // frame length (16 bits)
    // 
    Uic.i = 0;
    Uic.c[i_03lsbtomsb[1]] = fp[4]; // put in next-to-lsb
    Uic.c[i_03lsbtomsb[0]] = fp[5]; // put in lsb
    *framelen = Uic.i + 1; // no shifting - 16 bits' worth, and +1 because frame len in frame is one fewer than the total number of octets
    // kprMutex.lock();printf("pesult = frmlen%15d %15d ",*framelen, Uic.i);seedata(fp,20);printf("\n");fflush(stdout);kprMutex.unlock();
    klmprintf("pesult = frmlen%15d \n",*framelen);fflush(stdout);

    // 
    // bypass flag
    // 
    // no need to even use Uic - just look at the bit
    if ( fp[6] & 0x80 ) // point directly at the bit
    {
        *bypassFlag = 1;
    }	
    else	
    {	
        *bypassFlag = 0;
    }
    // kprMutex.lock();printf("pesult = bypas %15d %15d ",*bypassFlag, Uic.i);seedata(fp,20);printf("\n");fflush(stdout);kprMutex.unlock();
    klmprintf("pesult = bypas %15d \n",*bypassFlag);fflush(stdout);


    // 
    // protocolControlCommand bit (1 bit)
    // 
    // no need to even use Uic - just look at the bit
    if ( fp[6] & 0x40 ) // point directly at the bit
    {
        *protocolCommandControlFlag = 1;
    }	
    else	
    {	
        *protocolCommandControlFlag = 0;
    }
    //kprMutex.lock();printf("pesult = pccFlg%15d %15d ",*protocolCommandControlFlag, Uic.i);seedata(fp,20);printf("\n");fflush(stdout);kprMutex.unlock();
    klmprintf("pesult = pccFlg%15d \n",*protocolCommandControlFlag);fflush(stdout);

    // 2 bits reserve spare (already set to 0 by the memset above)

    // 
    // ocfFlag bit (1 bit)
    // 
    // no need to even use Uic - just look at the bit
    if ( fp[6] & 0x08 ) // point directly at the bit
    {
        *ocfFlag = 1;
    }	
    else	
    {	
        *ocfFlag = 0;
    }
    // kprMutex.lock();printf("pesult = ocfFlg%15d %15d ",*ocfFlag, Uic.i);seedata(fp,20);printf("\n");fflush(stdout);kprMutex.unlock();
    klmprintf("pesult = ocfFlg%15d \n",*ocfFlag);fflush(stdout);


    // 
    // vc sequence counter Octets(3 bits)
    // 
    Uic.i = 0;
    Uic.c[i_03lsbtomsb[0]] = fp[6] & 0x07; // put in lsb
    *vcSeqCounterOctets = Uic.i;
    // kprMutex.lock();printf("pesult = vcSqO %15d %15d ",*vcSeqCounterOctets, Uic.i);seedata(fp,20);printf("\n");fflush(stdout);kprMutex.unlock();
    klmprintf("pesult = vcSqO %15d \n",*vcSeqCounterOctets);fflush(stdout);

    // 
    // assign vc frame counter based on the number of vc counter octets
    // 
    int liVcSeqCounterOctets = *vcSeqCounterOctets; // save this value for speed
    LLllc.ll = 0ll;
    for ( int i = 0 ; i < liVcSeqCounterOctets ; i ++ )
    {
        // copy sequence counter octets (total of vcSeqCounterOctets octets) !!!! from MSB to LSB !!! into frame starting after the frame header
        // if 3 octets, put it into 2,1,0 ; if 2 octets put it into 1,0 if 7 octets put it into 6,5,4,3,2,1,0 where 0 is lsb and endianlonglonglsbtomsb[] is the sequence of LSB to MSB based on endian-ness
        LLllc.c[endianlonglonglsbtomsb[(liVcSeqCounterOctets - 1) - i]] = fp[FRAME_HEADER_LENGTH + i];
    }
    *vcSequenceCount = LLllc.ll; // assign value to long long
    // kprMutex.lock();printf("pesult = COUNT %15lld %15lld ",*vcSequenceCount, LLllc.ll);seedata(*framelen,20);printf("\n");fflush(stdout);kprMutex.unlock();
    klmprintf("pesult = COUNT %15lld vcid %d vcfco %d\n ",*vcSequenceCount,lvcid, liVcSeqCounterOctets);fflush(stdout);
    //
    // validate frame counter if exist and not FRAME SERVICE masterchan or vcid. masterchan and vcid already verified above
    //
    if ( lvcid == 63 || // do no frame counter checks if OID frame
            liVcSeqCounterOctets == 0 // no frame count octets
            // as of dec 5 2017 i have decided to check frame counts for vc/mc frame service since i hafta be able to determine the optional "frame loss" flags || lisFrameServiceFrame // or this is a frame service frame
       ) // if oid OR no frame count OR mcid or vcid is FRAME SERVICE 
    {
        m_vcFrameServiceCounter = 0; // reset frame // do no frame counter checks
    }
    else
    {
        long long lrxdFrameCounter = LLllc.ll; // up to 56 bits @ 56 vc count VALUE
        long long int *lexpectedFrameCounter;
        if ( lvcid != 63) // in case you got here because of the liVcSeqCounterOctets==0 ONLY.
        {
            //
            // point at the right counter based on bypass flag
            //
            if ( *bypassFlag == 0 ) 
            {
                lexpectedFrameCounter = &lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_vcSeqCtrlCounter;
            }
            else 
            {
                lexpectedFrameCounter = &lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_vcExpIntCounter;
            }
            klmprintf("FRAME COUNT COMPARISON vc %d pc %s rxd %lld expected %lld lost %lld frames.\n\n\n",lvcid, lptrphyschan->m_Name.c_str(), lrxdFrameCounter, *lexpectedFrameCounter, (lrxdFrameCounter - *lexpectedFrameCounter));fflush(stdout);
            if ( lrxdFrameCounter != *lexpectedFrameCounter ) // counter error
            {
                lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_mapmap[lmapid]->m_frameCountError = true; // this gets turned of by somebody
                klmprintf("\n\n\nFRAME COUNT vc %d ERROR pc %s rxd %lld expected %lld lost %lld frames.\n\n\n",lvcid, lptrphyschan->m_Name.c_str(), lrxdFrameCounter, *lexpectedFrameCounter, (lrxdFrameCounter - *lexpectedFrameCounter));fflush(stdout);
                *lexpectedFrameCounter = lrxdFrameCounter;
                // set error flags whose only indication is frame count error. these flags will be reset upon delivery (indication).
                klmprintf("kizq izlossflag set a\n");fflush(stdout);
                lptrphyschan->m_insertZoneLossFlag = true; // iz flag is per physchan
                lptrphyschan->m_MCmap[lMCid]->m_ocfLossFlag = true; // ocf flag is per masterchannel
                lptrphyschan->m_MCmap[lMCid]->m_McFrameServiceLossFlag = true; // set MC frame service loss flag, reset on delivery
                if ( lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_oneMapidOnThisVcid ) // mapa sdu loss flag ONLY true if counter anomaly AND ONLY ONE MAPID ON THIS VCID
                {
                    lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_mapmap[lmapid]->m_mapaSduFrameCountLossFlag = true; // octet stream is per mapid
                }
                lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_mapmap[lmapid]->m_octetStreamLossFlag = true; // octet stream is per mapid
                lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_vcidFrameServiceFrameLoss = true; // set vcFrameServiceFrameLossFlag; reset on delivery
            }
            *lexpectedFrameCounter = *lexpectedFrameCounter + 1; // bump expected count for next time
        }
    }
    *offsetOfFirstOctetPastVcCounters = (FRAME_HEADER_LENGTH + liVcSeqCounterOctets); // return index of first octet after header
    klmprintf("tfdf offset %d\n",*offsetOfFirstOctetPastVcCounters);fflush(stdout);

    return true;
}
//
// parse a tfdf that MAY be an encapsulated idle fill packet
// if entire frame is idle fill, copy header-and-idle-fill data to m_dfDataOnly so it is a whole parseable packet
// return bool true if normal frame (not oid frame and not truncated)
//
#ifndef PTFBITFIELDREWRITTEN
bool mibclass::mibParseFrame(kphysicalChannel *lptrphyschan, unsigned char *rxbuf, int rxlen, bool *isTruncatedFrame, bool *isOidFrame)
{
    bool lisFrameServiceFrame = false; // skip some stuff if this is a frame service frame
    *isTruncatedFrame	= false; // flag to say frame was truncated (method returns false to check these flags)
    *isOidFrame	= false; // flag to say frame was an OID frame (method returns false to check these flags)
    m_fhpLvo = 0; // init to zero in case there isn't one in the frame
    m_pvn = packetInfoMib.m_minimumValidPvn;

    m_bitfuncs.putAddr ( rxbuf );
    m_version_id = m_bitfuncs.get ( 0,  4 );                // 4 bits  @ 0 version num
    m_scid = m_bitfuncs.get ( 4, 16 );                      // 16 bits @ 4 spacecraft id
    m_dest_src = m_bitfuncs.get ( 20, 1 );                  // 1 bit   @ 20 src/dest id
    m_vcid = m_bitfuncs.get ( 21, 6 );                      // 6 bits  @ 21 vcid
    m_mapid = m_bitfuncs.get ( 27, 4 );                     // 4 bits  @ 27 mapid
    m_endOfTransferHeaderFlag = m_bitfuncs.get ( 31, 1 );   // 1 bit   @ 31 end of tf pr hdr flag - 0 if not truncated to 4 octets, 1 if it is; for now it isn't

    /*
       if ( ! lptrphyschan->m_Valid_Spacecraft_IDs[m_scid] )
       {
       klmprintf("INVALID SPACECRAFT ID of %d on physchan %s \n",m_scid,lptrphyschan->m_Name.c_str());fflush(stdout);
       return false;
       }
       */

    int lMCid = (m_version_id * 65536) + m_scid;
    int lvcid = m_vcid; // depending on the setting in the VCID

    // 
    // verify mcid, vcid since obviously physchan is good
    //

    bool goodMcidAndVcid = false;
    std::map <int,kmasterChannel *>::iterator lmcidIt = lptrphyschan->m_MCmap.find ( lMCid ); // see if MCid exists
    if ( lmcidIt != lptrphyschan->m_MCmap.end() ) // MC id found, check for vcid
    {
        std::map <int,kvcid *>::iterator lVcidIt = lmcidIt->second->m_vcidmap.find ( lvcid ); // if vcid object exists
        //
        // check vcid exists. 
        // MAKE EXCEPTION for vcid 63.
        //
        if ( lVcidIt != lmcidIt->second->m_vcidmap.end() || lvcid == 63 ) // found it - mcid and vcid are good
        {
            goodMcidAndVcid = true;
        }
        else
        {
            klmprintf("physchan %s MCID %d received unmapped Vcid %d - dropping frame\n", lptrphyschan->m_Name.c_str(),lMCid, lvcid );fflush(stdout);
        }
    }
    else
    {
        klmprintf("physchan %s received unmapped MCID %d - dropping frame\n", lptrphyschan->m_Name.c_str(),lMCid );fflush(stdout);
    }
    if ( goodMcidAndVcid != true ) // either mcid or vcid is bad
    {
        return false;
    }

    if ( m_endOfTransferHeaderFlag == 1 ) // truncated frame - NEVER HAS IZ - since the mib parameter is TOTAL FRAME LENGTH
    {	
        m_ocfPresent = 0;		// no ocf in truncated frames since there's no bit flag to flag its presence/absence
        m_ocfLen = 0; 	// for math
        // if this flag is set the only thing that matters is the data which is of length 2 or 3
        // depending on whether the overall length is 7 or 8, which you don't know until you know the vcid
        *isTruncatedFrame	= true; // flag to say frame was truncated (method returns false to check these flags)
        // copy the data and length-of-JUST-the-data-without-the-ostensibly-one-octet-tfdf-header
        m_dfDataOnlyLen = lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_truncatedFrameTotalLength - 4; // -4 is 4-octet truncated header and 1-octet tfdf header. either 7 or 8 total frame len means 2 or 3 octet data len
        memcpy ( m_dfDataOnly, &rxbuf[4], m_dfDataOnlyLen ); // m_dfDataOnlyLen is JUST the data, not the header. 
    }
    else // NOT a truncated frame
    {
        if ( lvcid == 63 ) // OID vcid will never be a truncated frame
        {
            *isOidFrame	= true; // flag to say frame was an OID frame (method returns false to check these flags)
        }
        // if NOT TRUNCATED frame, assign other optional field lengths
        // assign mib values from lmasterchan/vcid/lmapid
        // verify mcid, vcid, mapid and report error if invalid
        m_izLen = lptrphyschan->m_Isochronous_Insert_Zone_Length;
        if ( lvcid == 63 ) // OID vcid will never be a truncated frame
        {
            m_secHdrLen = 0;
            m_secTrlrLen = 0;
            m_vcFrameCountOctets = 0; // 4.2.8.4 note 1 - "it is not required to maintain a Virtual Channel frame count for OID frames" so i've made OID frames have ZERO frame count octets
        }
        else
        {
            m_secHdrLen = lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_LengthOfSpaceDataLinkSecurityHeader;
            m_secTrlrLen = lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_LengthOfSpaceDataLinkSecurityTrailer;
        }
        m_fecfLen = lptrphyschan->m_Frame_Error_Control_Length;  
        // end of optional field lengths for non-truncated frame

        // 
        // verify valid mapid (vcid 63 mapid must be zero)
        // 
        if ( lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_mapmap[m_mapid] == NULL )
        {
            klmprintf("error - mibParseFrame detected bad mapid in GMAPID %s/%d/%d/%d\n",lptrphyschan->m_Name.c_str(), lMCid, lvcid, m_mapid);fflush(stdout);
            return false; // bad mapid
        }
        //
        // get m_protocolCommandControlFlag while you've already validated that the vcid is NOT 63 and the mapid is good
        //
        lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_mapmap[m_mapid]->m_protocolCommandControlFlag = m_bitfuncs.get ( 49, 1 );  // 1 bit   @ 49 command/control flag 
        m_totalFrameLen = m_bitfuncs.get ( 32, 16 ) + 1;        // 16 bit  @ 32 total frame length ( in frame it's total octets minus one so add one once you get it from frame
        m_bypassFlag = m_bitfuncs.get ( 48, 1 );                // 1 bit   @ 48 bypass flag 4.1.2.9.1.1
        m_reserveSpares = m_bitfuncs.get ( 50, 2 );             // 2 bits  @ 50 reserve spares set to 000 as per 4.1.2.9.2
        // as of april 2017 1-bit ocfPresent flag
        m_ocfPresent = m_bitfuncs.get ( 52, 1 );            // 1 bit   @ 52 is a flag that says it's there or not. hardcoded length of 4
        // set ocf len based on flag in data
        m_ocfLen = ( m_ocfPresent==0?0:MAX_OCF_LENGTH ); // frame ocf - if flag = 0 len = 0 if flag = 1 len = MAX_OCF_LENGTH
        //
        // get ocf data later in method
        //
        m_vcFrameCountOctets = m_bitfuncs.get ( 53, 3 );          // 3 bits  @ 53 vc count LENGTH

        klmprintf("klmdebug frame counter octets = %d\n",m_vcFrameCountOctets);fflush(stdout);
        if ( lptrphyschan->m_MCmap[lMCid]->m_mcFrameService || // frame service master channel
                lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_VcidFrameService  // frame service virtual channel
           )
        {
            lisFrameServiceFrame = true; // this is a frame service frame
        }
        //
        // validate frame counter if exist and not FRAME SERVICE masterchan or vcid. masterchan and vcid already verified above
        //
        if ( lvcid == 63 || // do no frame counter checks if OID frame
                m_vcFrameCountOctets == 0 // no frame count octets
                // as of dec 5 2017 i have decided to check frame counts for vc/mc frame service since i hafta be able to determine the optional "frame loss" flags || lisFrameServiceFrame // or this is a frame service frame
           ) // if oid OR no frame count OR mcid or vcid is FRAME SERVICE 
        {
            m_vcFrameServiceCounter = 0; // reset frame // do no frame counter checks
        }
        else
        {
            int lrxdFrameCounter = m_bitfuncs.get ( 56, ( 8 * m_vcFrameCountOctets ) ); // up to 56 bits @ 56 vc count VALUE
            long long int *lexpectedFrameCounter;
            if ( lvcid != 63) // already checked this above, but ....
            {
                //
                // point at the right counter based on bypass flag
                //
                if ( m_bypassFlag == 0 ) 
                {
                    lexpectedFrameCounter = &lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_vcSeqCtrlCounter;
                }
                else 
                {
                    lexpectedFrameCounter = &lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_vcExpIntCounter;
                }
                if ( lrxdFrameCounter != *lexpectedFrameCounter ) // counter error
                {
                    lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_mapmap[m_mapid]->m_frameCountError = true; // this gets turned of by somebody
                    klmprintf("\n\n\nFRAME COUNT vc %d ERROR pc %s rxd %d expected %lld lost %lld frames.\n\n\n",lvcid, lptrphyschan->m_Name.c_str(), lrxdFrameCounter, *lexpectedFrameCounter, ((long long int)lrxdFrameCounter - *lexpectedFrameCounter));fflush(stdout);
                    *lexpectedFrameCounter = lrxdFrameCounter;
                    // set error flags whose only indication is frame count error. these flags will be reset upon delivery (indication).
                    klmprintf("kizq izlossflag set b\n");fflush(stdout);
                    lptrphyschan->m_insertZoneLossFlag = true; // iz flag is per physchan
                    lptrphyschan->m_MCmap[lMCid]->m_ocfLossFlag = true; // ocf flag is per masterchannel
                    lptrphyschan->m_MCmap[lMCid]->m_McFrameServiceLossFlag = true; // set MC frame service loss flag, reset on delivery
                    lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_mapmap[m_mapid]->m_octetStreamLossFlag = true; // octet stream is per mapid
                    lptrphyschan->m_MCmap[lMCid]->m_vcidmap[lvcid]->m_vcidFrameServiceFrameLoss = true; // set vcFrameServiceFrameLossFlag; reset on delivery
                }
                *lexpectedFrameCounter = *lexpectedFrameCounter + 1; // bump expected count for next time
            }
        }

        m_primaryHeaderLen = FRAME_PRIMARY_HEADER_OCTETS + m_vcFrameCountOctets; // length of just the transfer frame primary header (allowing for variable vc conter field length)

        //
        // since security header is per vcid i hafta see how many bytes of header and how many bytes of trailer we expect for this frame's vcid
        //
        //

        // insert zone offset
        m_izOffset = m_primaryHeaderLen;

        if ( m_izLen > 0 )  
        {
            memcpy ( m_izData, &rxbuf[m_izOffset],m_izLen ); // mib length
        }

        // security header offset

        m_secHdrOffset = m_izOffset + m_izLen;

        if ( m_secHdrLen > 0 ) // per vcid 
        {
            memcpy ( m_secHdrData, &rxbuf[m_secHdrOffset],m_secHdrLen ); // mib length
        }

        // transfer frame data field offset
        ///////////////////// data must be calculated////////////////////////////////////
        //  data field header
        m_dfHdrOffset = m_secHdrOffset + m_secHdrLen;

        //
        // if no data field (frame len is the length of the header MINUS possible security header minus possible fecf minus possible ocf) put safe values in all expected-data fields 
        //
        if ( m_dfHdrOffset >= (m_totalFrameLen - m_secTrlrLen - m_ocfLen - m_fecfLen)) // apparently this frame does not contain any data - it's just a legal header
        {
            m_dfHdrOffset = -1;
            m_constrRules = -1;
            m_protocolId = -1;
            m_dfHdrLen = -1;
            m_fhpLvo = -1;
            m_dfDataOffset = -1;
            m_dfDataOnlyLen = -1;
        }
        else // ok to do the rest of this stuff
        {
            m_dfHdrLen = 0; // assume no header
            int bytesLeftInTFDFincludingThisOne = rxlen - m_dfHdrOffset - m_secTrlrLen - m_ocfLen - m_fecfLen; // including octet AT rxlen[m_dfHdrOffset], how many octets are left in TFDF?
            if ( isEncapsulatedIdlePacket(rxbuf,m_dfHdrOffset,bytesLeftInTFDFincludingThisOne))
            {
                // get idle packet length, copy data (why?), and continue to extract other parts of frame (sectrlr, ocf, fecf)
                // make sure these values are good to calculate subsequent field offsets
                m_dfHdrLen = (rxbuf[m_dfHdrOffset] & 0x03) + 1; // E0/E1/E2 plus length byte(s)
                // should never be a case where the encapsulated idle packet doesn't have all its length bytes
                m_dfDataOnlyLen = getPacketLength(&rxbuf[m_dfHdrOffset],  rxlen ) - m_dfHdrLen; // always enough bytes to get a length of this encapsulated idle packet
                memcpy ( m_dfDataOnly, &rxbuf[m_dfHdrOffset],m_dfDataOnlyLen + m_dfHdrLen ); // copy entire datafield (including header) into m_dfDataOnly, since the whole packet is encapsulated idle data
            }
            else // TODO how do i know if there's data? if ( m_dfDataOnlyLen > 0 ) // if there is actual data
            {
                m_bitfuncs.putAddr ( &rxbuf[m_dfHdrOffset] ); // point at transfer frame data header
                m_constrRules = m_bitfuncs.get ( 0, 3 );  // 3 bits  @ (tfph + vc frame count)
                m_protocolId = m_bitfuncs.get ( 3, 5 ); // get first (or only) protocolId octet
                /*
                   as of oct 2016 spec the extended protocol id does not exist any more. so the dfheaderlen will always be 1 so far, regardless of the 0-31 value of the protocol id
                   if ( m_protocolId < 31 )
                   {
                   m_dfHdrLen = 1; // 1 octet header
                   }
                   else // protcol Id >= 31
                   {
                   m_protocolId +=  m_bitfuncs.get ( 8, 8 ); // remainder in the 2nd octet
                   m_dfHdrLen = 2; // 2-octet header
                   }
                   above code replaced below
                   */
                m_dfHdrLen = 1; // 1 octet header (replaces commented out code above)

                // some construction rules need fhp/lvo
                if ( m_constrRules ==    CR_000_SPANNING_DATA_UNITS
                        || m_constrRules == CR_001_MAPA_SDU_STARTS_MAY_END
                        || m_constrRules == CR_010_CONTINUING_MAPA_SDU_MAY_END )
                {
                    m_fhpLvo = m_bitfuncs.get ( 8 * m_dfHdrLen, 16 );
                    m_dfHdrLen += 2; // 2 MORE octet header
                }
                // data field data
                m_dfDataOffset = m_dfHdrOffset + m_dfHdrLen;
                //
                // calculate data length from totalFrameLength minus optional Fields
                //
                m_dfDataOnlyLen = m_totalFrameLen // frame total length
                    - FRAME_PRIMARY_HEADER_OCTETS   // frame constant header octets (TODO end-of-primary-header)
                    - m_vcFrameCountOctets // frame vc counter octets
                    - m_izLen          // MIB insert zone
                    - m_secHdrLen      // MIB security header
                    - m_dfHdrLen           // frame tfdf header constr rules/protocolId 0-31
                    - m_secTrlrLen     // MIB security trailer
                    - m_ocfLen       // frame ocf
                    - m_fecfLen;       // MIB security trailer




                klmprintf("parseframe says m_dfDataOnlyLen %d m_totalFrameLen %d m_vcFrameCountOctets %d m_izLen %d m_secHdrLen %d m_dfHdrLen %d m_secTrlrLen %d m_ocfLen %d m_fecfLen %d\n",
                        m_dfDataOnlyLen ,  m_totalFrameLen , m_vcFrameCountOctets , m_izLen ,    m_secHdrLen ,  m_dfHdrLen ,  m_secTrlrLen ,  m_ocfLen,  m_fecfLen);fflush(stdout);
                klmprintf("parseframe says izOffset %d securityHdrOffset %d dfHdroffset %d dfCR %d dfhdrPID %d df offset is %d, df len is %d\n",
                        m_izOffset,      m_secHdrOffset, m_dfHdrOffset, m_constrRules, m_protocolId, m_dfDataOffset,m_dfDataOnlyLen );
                fflush ( stdout );

                memcpy ( m_dfDataOnly, &rxbuf[m_dfDataOffset],m_dfDataOnlyLen ); // m_dfDataOnlyLen is JUST the data, not the header
            }
            ///////////////////// data must be calculated////////////////////////////////////

            // security trailer offset (offset from data field HEADER, not data field DATA)

            m_secTrlrOffset = m_dfHdrOffset + m_dfHdrLen + m_dfDataOnlyLen;

            if ( m_secTrlrLen > 0 ) // per vcid now
            {
                memcpy ( m_secTrlrData,  &rxbuf[m_secTrlrOffset],m_secTrlrLen ); // mib length
            }

            // ocf offset

            m_ocfOffset = m_secTrlrOffset + m_secTrlrLen; // mib length
            if ( m_ocfLen > 0 ) // MIB parameter
            {
                memcpy ( m_ocfData,&rxbuf[m_ocfOffset],m_ocfLen );
            }
            // fecf offset

            m_fecfOffset = m_ocfOffset + m_ocfLen; // mib length
            if ( m_fecfLen > 0 )
            {
                memcpy ( m_fecfData, &rxbuf[m_fecfOffset], m_fecfLen );
            }
        }
    }
    return true; // return flag indicating data is valid
}
#endif // #ifndef PTFBITFIELDREWRITTEN
//
// this is the function that gets called when a MAP_CHANNEL_Minimum_ms_delay_to_complete_TFDF timer expires
//
void kmapid::mapTxStartedTfdfTimerExpired(void)
{
    klmprintf("maptxstarted %d called at %d copytooutputindex %d\n",m_map_MAPID, fromstartsecs(),m_copyToOutputIndex);fflush(stdout);
    // if (something in buffer)
    // {
    // 	if fixed len, idle fill and tx, and empty
    // 	if variable length, tx and empty
    // }
    // else (nothing in buffer) {}
    // reset variables (in either case)

    if ( m_copyToOutputIndex > 0 ) // something in tx buffer AND past time to transmit it (since it was called by a routine that asks checkForMapData which includes is-it-time-to-transmit queries
    {
        //
        // idle fill (if fixed length)
        // fhplvo != 0 ONLY if idlefilling endspan. otherwise it stays at zero
        // 
        //
        if ( m_fixedlen && m_ccsdsPacket && m_endSpan )
        {
            m_mapfhplvo = m_copyToOutputIndex; // this is where the new idle packet would start
        }
        //
        // since timeout, construct construction rules from flags
        //
        constructPerMapHeader( m_txBufStartsWithContinuation, false, !m_fixedlen /* !m_fixed since constructPerMapHeader is looking for isVariable flag*/ , m_fhplvoOffset, m_mapfhplvo);
        int lroomLeftInOutput = m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR - m_mapid_frameCounterOctets - m_copyToOutputIndex; // total octets available in the tx assembly buffer
        // int lroomLeftInOutput = m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets - m_mapid_frameCounterOctets - m_mapid_ocfLength - m_copyToOutputIndex; // total octets available in the tx assembly buffer
        //		klmprintf("kzb before idle fill roomleft = %d ctoOutIndex %d \n", lroomLeftInOutput, m_copyToOutputIndex);fflush(stdout);
        //
        // when you idle fill you're assuming that what's in the txassemblybuf is the end of a completed unit.
        // therefore when you idle fill you set the FHP to point to the start of the idle packet
        //
        if ( m_fixedlen )
        {
            // m_map_MaximumTfdfLength_SANS_QoS_FRAME_COUNT_OCTETS_AND_TFDF_HDR is what the total TFDF len should be (includes header and datafield)
            idleFillHere(&m_TxAssemblyBuf[ m_copyToOutputIndex ], lroomLeftInOutput, m_map_pcOidData );  // idlefill until end (txassembuf does not contain header)
            m_copyToOutputIndex += lroomLeftInOutput;  // since you know you have at least ONE header, include the header in the returned length
        }
        // else if variable length - no idle fill, just tx to the queue as is
        //
        TXtoQueue(m_txBypassFlag, "tx from mapTxStartedTfdfTimerExpired() "); // TODO eliminate status
        // klm918 decrementedUponGet() m_myVcidParent->decrementMCidOcfDeliveryCount(); // decrement the delivery count of the OCF since you just delivered it
        m_myVcidParent->resetVcidOidTimer(); // txed on this vcid; reset its timeout and the OID timeout
    }
    else
    {
        // else NOTHING in the buffer (THIS SHOULD NEVER HAPPEN since the timer is ONLY moved away from FOREVER_IN_THE_FUTURE when SOMETHING is in the buffer) - just reset variables
        klmprintf("mapTxStartedTfdfTimerExpired() at %d called WITH EMPTY BUFFER - no tx, just resetting variables\n",fromstartsecs());fflush(stdout);
    }
    // reset txassemblybuf offset pointer
    m_copyToOutputIndex = 0; 
    m_txBufStartsWithContinuation = false; // empty tx assembly buffer now
    m_usTimeToTransmitStartedTfdf = FOREVER_IN_THE_FUTURE; // turn off timer
    m_mapfhplvo = 0xffff; // FHP is first octet of idle fill packet 
}
/*void kmapid::mKLMQapTxStartedTfdfTimerExpired(kphysicalChannel *kpcptr,kmasterChannel *kMCptr, kvcid *kvcptr, kmapid *kmapidptr )
  {
// if (something in buffer)
// {
// 	if fixed len, idle fill and tx, and empty
// 	if variable length, tx and empty
// }
// else (nothing in buffer) {}
// reset variables (in either case)

if ( m_copyToOutputIndex > 0 ) // something in tx buffer AND past time to transmit it (since it was called by a routine that asks checkForMapData which includes is-it-time-to-transmit queries
{
//
// idle fill (if fixed length)
// fhplvo != 0 ONLY if idlefilling endspan. otherwise it stays at zero
// 
//
if ( m_fixedlen && m_ccsdsPacket && m_endSpan )
{
m_mapfhplvo = m_copyToOutputIndex; // this is where the new idle packet would start
}
//
// since timeout, construct construction rules from flags
//
constructPerMapHeader( m_txBufStartsWithContinuation, false, !m_fixedlen  , m_fhplvoOffset, m_mapfhplvo);// !m_fixed since constructPerMapHeader is looking for isVariable flag

int lroomLeftInOutput = m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets - m_mapid_frameCounterOctets - m_mapid_ocfLength - m_copyToOutputIndex; // total octets available in the tx assembly buffer
//		klmprintf("kzb before idle fill roomleft = %d ctoOutIndex %d \n", lroomLeftInOutput, m_copyToOutputIndex);fflush(stdout);
//
// when you idle fill you're assuming that what's in the txassemblybuf is the end of a completed unit.
// therefore when you idle fill you set the FHP to point to the start of the idle packet
//
if ( m_fixedlen )
{
// m_maxHeaderlessDataFieldOctetsNotIncludingOcfOrFrameCountOctets is what the total TFDF len should be (assumes one header and one headerless datafield)
idleFillHere(&m_TxAssemblyBuf[ m_copyToOutputIndex ], lroomLeftInOutput, m_map_pcOidData );  // idlefill until end (txassembuf does not contain header)
m_copyToOutputIndex += lroomLeftInOutput;  // since you know you have at least ONE header, include the header in the returned length
}
// else if variable length - no idle fill, just tx as is
//
TX("tx from mKLMQapTxStartedTfdfTimerExpired(params) "); // TODO eliminate status
// klm918 decrementedUponGet() m_myVcidParent->decrementMCidOcfDeliveryCount(); // decrement the delivery count of the OCF since you just delivered it
}
else
{
// else NOTHING in the buffer - just reset variables
// klmprintf("mKLMQapTxStartedTfdfTimerExpired(params) called WITH EMPTY BUFFER - no tx, just resetting variables\n");fflush(stdout);
}
// reset txassemblybuf offset pointer
m_copyToOutputIndex = 0; 
m_txBufStartsWithContinuation = false; // empty tx assembly buffer now
m_usTimeToTransmitStartedTfdf = FOREVER_IN_THE_FUTURE; // turn off timer
m_mapfhplvo = 0xffff; // FHP is first octet of idle fill packet 
}
*/
char *kphysicalChannel::PCktree(void)
{
    sprintf(m_parentstr,"%s",m_Name.c_str());
    return m_parentstr;
}
char *kmasterChannel::mcktree(void)
{
    sprintf(m_parentstr,"%s.%d",m_parentphyschan->PCktree(),m_MC_ID);
    return m_parentstr;
}
char *kvcid::vcktree(void)
{
    sprintf(m_parentstr,"%s.%d",m_myMCID->mcktree(),m_VCID);
    return m_parentstr;
}
char *kmapid::mapktree(void)
{
    sprintf(m_parentstr,"%s.%d",m_myVcidParent->vcktree(),m_map_MAPID);
    return m_parentstr;
}
void mibclass::seeEverything ( void )
{
    kprMutex.lock();
    printf ( "m_version_id = %d\n", m_version_id );
    printf ( "m_scid = %d\n", m_scid );
    printf ( "m_dest_src = %d\n", m_dest_src );
    printf ( "m_vcid = %d\n", m_vcid );
    printf ( "m_mapid = %d\n", m_mapid );
    printf ( "m_endOfTransferHeaderFlag = %d\n", m_endOfTransferHeaderFlag );
    printf ( "m_totalFrameLen = %d\n", m_totalFrameLen );
    printf ( "m_bypassFlag  = %d\n", m_bypassFlag );
    printf ( "m_reserveSpares = %d\n", m_reserveSpares );
    printf ( "m_ocfPresent = %d\n", m_ocfPresent );
    printf ( "m_ocfLen = %d\n", m_ocfLen );
    printf ( "m_ocfData = " );
    seedata ( ( unsigned char * ) m_ocfData,m_ocfLen );
    printf ( "\n" );
    printf ( "m_vcFrameCountOctets = %d\n", m_vcFrameCountOctets );
    printf ( "m_vcFrameServiceCounter = %d\n", m_vcFrameServiceCounter );
    printf ( "m_izLen = %d\n", m_izLen );
    printf ( "m_izData = " );
    seedata ( ( unsigned char * ) m_izData,m_izLen );
    printf ( "\n" );
    printf ( "m_secHdrLen = %d\n", m_secHdrLen );
    printf ( "m_secHdrData = " );
    seedata ( ( unsigned char * ) m_secHdrData,m_secHdrLen );
    printf ( "\n" );
    printf ( "m_protocolId = %d\n", m_protocolId );
    printf ( "m_constrRules = %d\n", m_constrRules );
    printf ( "m_fhpLvo = %d\n", m_fhpLvo );
    printf ( "m_dfDataOnlyLen = %d\n", m_dfDataOnlyLen );
    printf ( "m_dfDataOnly = " );
    seedata ( ( unsigned char * ) m_dfDataOnly,m_dfDataOnlyLen );
    printf ( "\n" );
    printf ( "m_secTrlrLen = %d\n", m_secTrlrLen );
    printf ( "m_secTrlrData = " );
    seedata ( ( unsigned char * ) m_secTrlrData, m_secTrlrLen );
    printf ( "\n" );
    printf ( "m_fecfLen = %d\n", m_fecfLen );
    printf ( "m_fecfData = " );
    seedata ( ( unsigned char * ) m_fecfData,m_fecfLen );
    printf ( "\n" );
    fflush(stdout);
    kprMutex.unlock();
}
// 
// 
//  handle turnaround tx-whatcha-rx situations by dinking indications to call *.* requests
// 
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// 
// requests called from sdu indications
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// 
// 
void mibclass::map_MIB_OctetStream_Request ( unsigned char * onlyDataNoHeader, /* int onlyDataNoHeaderLen replaced oct 30,2017 with managed mapid parameter m_map_octetStreamRequestLength*/ gmapid_t gmapid/* 2/21/2018 4:25pm greg kazz email removes this param, int sequenceControl0expedited1*/)
{
    mibclass::map_OctetStream_Request ( onlyDataNoHeader, /* int onlyDataNoHeaderLen replaced oct 30,2017 with managed mapid parameter m_map_octetStreamRequestLength*/ gmapid/* 2/21/2018 4:25pm greg kazz email removes this param, sequenceControl0expedited1*/);
}
void mibclass::map_MIB_MapaSDU_Request ( unsigned char * mapaSdu, int onlyDataNoHeaderLen, /* restored 20180522 mapa_sdu length replaced oct30,2017 with managed mapid parameter m_map_mapaSduLength */ gmapid_t GMAPID, int ltxSDU_ID, int sequenceControl0expedited1)
{
    mibclass::map_MapaSDU_Request ( mapaSdu, GMAPID, ltxSDU_ID, sequenceControl0expedited1); // call the one that gets txd
}
bool mibclass::map_MIB_P_Request ( unsigned char * onlyDataNoHeader, int onlyDataNoHeaderLen, gmapid_t gmapid, int packetVersionNumber, int ltxSDU_ID, int sequenceControl0expedited1 )
{
    klmprintf("map_MIB_P_Request tx SDU %d\n",ltxSDU_ID);fflush(stdout);
    return mibclass::map_P_Request ( onlyDataNoHeader, onlyDataNoHeaderLen, gmapid, packetVersionNumber, ltxSDU_ID, sequenceControl0expedited1 ); // call the one that gets txd
}
void mibclass::MIB_insert_request ( unsigned char * isochInsertZoneData, String lphyschan ) // length specified by MIB value PHYSICAL_CHANNEL_Isochronous_Insert_Zone_Length
{
    mibclass::insert_request ( isochInsertZoneData, lphyschan); // tx whatcha rx
}
void mibclass::MIB_ocfServiceRequest ( unsigned char * ocfRq, gvcid_t gvcid )
{
    mibclass::ocfServiceRequest ( ocfRq, gvcid ) ;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// packet, mapa sdu, octet stream, insert zone, ocf indications that call requests if tx-whatcha-rx is defined
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void kmapid::map_octetStream_indication(unsigned char *octetStreamData, gmapid GMAPID, /* 2/21/2018 4:25pm greg kazz email removes qos int qos, */bool octetStreamLossFlag, int verificationStatusCode)
{
    int loctetStreamLength = m_map_octetStreamDeliverLength; // sdu length is a managed parameter now

    kprMutex.lock();
    printf("octetStream_indication l%5d GMAPID %s-%6d-%1d-%1d Qos <removed> octetStreamLossflag %s VSC %s ",
            loctetStreamLength,  // len
            GMAPID.PHYSCHAN.c_str(),  // physchan
            ((GMAPID.TFVN * 65536) + GMAPID.SCID),  // mcid
            GMAPID.VCID, // vcid
            GMAPID.MAPID, // mapid
            // qos, // quality of service
            octetStreamLossFlag?"true":"false", // packet quality indictor
            verificationStatusCode == SDLS_ERROR_verificationStatusCode?(char *)"SDLS ERROR HEADER OR TRAILER UNMATCH":verStatCodeStr[verificationStatusCode]); // verification status code
    seedata(octetStreamData, loctetStreamLength); 
    printf("\n"); fflush(stdout);
    kprMutex.unlock();
#ifdef TRANSMIT_WHAT_YOU_RECEIVE
    MIB.map_MIB_OctetStream_Request ( octetStreamData, /* int onlyDataNoHeaderLen replaced oct 30,2017 with managed mapid parameter m_map_octetStreamRequestLength*/ GMAPID, m_txBypassFlag);
#endif // TRANSMIT_WHAT_YOU_RECEIVE
    m_frameCountError = false;
    m_octetStreamLossFlag = false; // reset to no-error situation
}
void kmapid::mapasdu_indication(unsigned char *mapaSdu, gmapid GMAPID, int qos, bool mapaSduLossFlag, int verificationStatusCode)
{
    int lmapasdulen = strlen((char *)mapaSdu) + 1; // changed 20180522 such that the mapa sdu SERVICE is intelligent enough to glean length info from the mapa_sdu itself. in this case i'm assuming the mapa_sdu is a nul-terminated string, and its length includes the nul.

    kprMutex.lock();
    printf("mapasdu_indication l%5d GMAPID %s-%6d-%1d-%1d Qos %d mapaSduLossflag %s VSC %s ",
            lmapasdulen,  // len
            GMAPID.PHYSCHAN.c_str(),  // physchan
            ((GMAPID.TFVN * 65536) + GMAPID.SCID),  // mcid
            GMAPID.VCID, // vcid
            GMAPID.MAPID, // mapid
            qos, // quality of service
            mapaSduLossFlag?"true":"false", // packet quality indictor
            verificationStatusCode == SDLS_ERROR_verificationStatusCode?(char *)"SDLS ERROR HEADER OR TRAILER UNMATCH":verStatCodeStr[verificationStatusCode]); // verification status code
    seedata(mapaSdu, lmapasdulen); 
    printf("\n"); fflush(stdout);
    kprMutex.unlock();
#ifdef TRANSMIT_WHAT_YOU_RECEIVE
    MIB.map_MIB_MapaSDU_Request ( mapaSdu, int onlyDataNoHeaderLen /*restored 20180522 mapa_sdu length replaced oct30,2017 with managed mapid parameter m_map_mapaSduLength */, GMAPID, dummyTxSDU_ID, m_txBypassFlag);
#endif // TRANSMIT_WHAT_YOU_RECEIVE
    m_completeMapaSdu = 0; // reset assumption back to true (1) after delivery of packet 
    m_frameCountError = false;
    m_mapaSduFrameCountLossFlag = false; // reset to no-error situation upon delivery
}
void kmapid::mapp_indication(unsigned char *packet, gmapid GMAPID, int packetVersionNumber, int QoS, bool packetQualityIndicatorError, int verificationStatusCode)
{
    int lpktlen = 0;
    int lmcid =  ((GMAPID.TFVN * 65536) + GMAPID.SCID);
    if ( ! packetQualityIndicatorError ) // if it's safe to get a packet length from this packet (not a delivery of a partial packet)
    {
        lpktlen = getPacketLength(packet,6);  // len
    }
    else
    {
        lpktlen = 7; // only print the header
    }

    kprMutex.lock();
    printf("mapp_indication l%5d GMAPID %s-%6d-%1d-%1d-%1d Qos %d pQIC %s VSC %s ",
            lpktlen,  // len
            GMAPID.PHYSCHAN.c_str(),  // physchan
            lmcid,  // mcid
            GMAPID.VCID, // vcid
            GMAPID.MAPID, // mapid
            packetVersionNumber, // pvn (in first octet)
            QoS, // quality of service
            packetQualityIndicatorError?"true":"false", // packet quality indictor: complete?
            verificationStatusCode == SDLS_ERROR_verificationStatusCode?(char *)"SDLS ERROR HEADER OR TRAILER UNMATCH":verStatCodeStr[verificationStatusCode]); // verification status code
    seedata(packet, lpktlen); 
    printf("\n"); fflush(stdout);
    kprMutex.unlock();
#ifdef TRANSMIT_WHAT_YOU_RECEIVE
    MIB.map_MIB_P_Request ( packet, lpktlen, GMAPID, packetVersionNumber, MIB.txSdu++, m_txBypassFlag );
#endif // TRANSMIT_WHAT_YOU_RECEIVE
    m_completePacket = 0; // reset assumption back to "no-loss" value (0) after delivery of packet 
    m_frameCountError = false;
}	
void kphysicalChannel::insertZoneIndication(unsigned char * izdata, String physchan, bool insertZoneFrameLossFlag)
{
    int lizlen = m_Isochronous_Insert_Zone_Length;
    kprMutex.lock();printf ( "insertZone_indication pc %s framelossFlag=%s data ",physchan.c_str(), insertZoneFrameLossFlag?"true":"false"); seedata ( izdata, lizlen ); printf ( "\n" ); fflush ( stdout );kprMutex.unlock();
#ifdef TRANSMIT_WHAT_YOU_RECEIVE 
    MIB.MIB_insert_request ( izdata, physchan);
#endif // TRANSMIT_WHAT_YOU_RECEIVE
    klmprintf("kizq izlossflag cleared\n");fflush(stdout);
    m_insertZoneLossFlag = false; // reset to no-error situation
} 
void kmasterChannel::masterChannelOcfIndication(unsigned char *ocfData, gvcid GVCID, bool ocfLossFlag)
{
    kprMutex.lock();printf("masterChannelOcfIndication ocf %s-%d-%d lossflag %s data ",GVCID.PHYSCHAN.c_str(), (GVCID.TFVN * 65536) + GVCID.SCID, GVCID.VCID,ocfLossFlag?"true":"false");seedata(ocfData,4);printf("\n");fflush(stdout);kprMutex.unlock();
#ifdef TRANSMIT_WHAT_YOU_RECEIVE 
    MIB.MIB_ocfServiceRequest ( ocfData, GVCID );
#endif // TRANSMIT_WHAT_YOU_RECEIVE
    m_ocfLossFlag = false; // reset to no-error situation
}
