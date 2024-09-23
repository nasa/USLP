#include<stdio.h>
#include <map>
#include "mib.cc"
#include <errno.h>
#include <pthread.h>

mibclass MIB;
extern sem_t frameEvery5s_sem;
// week of jan 27 2017 - removing extended protocol id octet
const char *truncatedRawData = "TRUNCATED_RAW_DATA";
void insertPacketLenPvnIntoPrimaryHeaderSpot ( char * buf, int len , int pvn)
{
    buf[0] = pvn;
    len = len - 7; // ccsds packet length
    if ( len < 255 )
    {
        buf[4] = 0;
        buf[5] = len;
    }
    else
    {
        buf[4] = ( int ) len / 256;
        buf[5] = len % 256;
    }
}

extern void seeframe(unsigned char *data,int datalen);
extern int klmglobalFrameSize;
extern char	klmglobalFrameType[];
int main ( int argc, char * argv[] )
{
    String lphyschan = "PC1";
    String lphyschan2 = "PC2";
    unsigned char data01[65536];
    unsigned char ocfdata[5];
    char *configfilename = (char *)"./mibconfig";


    gmapid GMAPIDv0m0pkt,G2MAPIDv0m0pkt,GMAPIDv0m15mapasdu,GMAPIDv7m8octTrunc,GMAPID_62_1varpkt, GMAPID_62_14varsdu;
    gvcid GVCID7,GVCID51,G2VCID0;
    gmasterChannelId MCID51;

    GVCID51.set(lphyschan,12,42,51);
    GVCID7.set(lphyschan,12,42,7); // set for vcid 7
    MCID51.set("PC1",12,51); // mcid just for frame service frames

    G2VCID0.set(lphyschan2,12,42,0); // set for pc2 vcid 0


    if ( argc > 1 )
    {
        configfilename = argv[1];
    }
    MIB.readMibConfig ( configfilename );

    strcpy((char *)ocfdata,(char *)"<oc>");
    MIB.ocfServiceRequest(ocfdata, GVCID7); // one-off on vcid 7

    GMAPIDv0m0pkt.set (lphyschan, 12, 42, 0, 0);        // physical channel, tf version, spacecraft id, vcid, mapid
    G2MAPIDv0m0pkt.set (lphyschan2, 12, 42, 0, 0);        // physical channel, tf version, spacecraft id, vcid, mapid
    GMAPIDv0m15mapasdu.set (lphyschan, 12, 42, 0, 15);  // physical channel, tf version, spacecraft id, vcid, mapid
    GMAPIDv7m8octTrunc.set (lphyschan, 12, 42, 7, 8);        // physical channel, tf version, spacecraft id, vcid, mapid

    GMAPID_62_1varpkt.set (lphyschan, 12, 42, 62, 1 ); // physical channel, tf version, spacecraft id, vcid, mapid
    GMAPID_62_14varsdu.set (lphyschan, 12, 42, 62, 14 ); // physical channel, tf version, spacecraft id, vcid, mapid
    MIB.mibPutFecf ( (unsigned char *) "<fe>", "PC1");

    // pc2 is loaded
    MIB.insert_request ( (unsigned char *) "<insert_daTA>", "PC2");
    MIB.mibPutFecf ( (unsigned char *) "<f2>", "PC2");
    strcpy((char *)ocfdata,(char *)"(O2)");
    MIB.ocfServiceRequest(ocfdata, G2VCID0); // every fixed frame on pc2 vcid 0 
    MIB.putSecurityHeader((unsigned char *)"<schd>",G2VCID0);
    MIB.putSecurityTrailer((unsigned char *)"<sctrLR>",G2VCID0); 

    int runwhiletrue = 1;
    MIB.start((void *)&runwhiletrue);
    for ( int msgnumber = 1 ; msgnumber < 10; msgnumber++ ) // 01 to 09 so no repeating digits
    {
        int packetVersionNumber = 0;
        int SDU_ID = 2;
        int seqEx = 1;
        int ldatalen;

        //
        //  bool map_P_Request ( unsigned char * onlyDataNoHeader, int onlyDataNoHeaderLen, gmapid_t gmapid, int packetVersionNumber, int ltxSDU_ID, int sequenceControl0expedited1 )
        sprintf((char *)data01,"#pkt##UNCOPYRIGHTABLE##");
        ldatalen = strlen((const char*)data01);
        sprintf((char *)&data01[ldatalen-2],"%02d",msgnumber);
        insertPacketLenPvnIntoPrimaryHeaderSpot((char *)data01, ldatalen, 0x00); // pvn is 1st 3 bits of octet
        // seeframe(data01,ldatalen);
        // 
        // map packet v0 m0 fixed len
        // 

        MIB.map_P_Request(data01, ldatalen , GMAPIDv0m0pkt, packetVersionNumber, SDU_ID, seqEx ); // let the managed parameter determine what kinda data it is. only data, no header.

        seqEx = 0;

        sprintf((char *)data01,"#PKT##uncopyrightable##");
        ldatalen = strlen((const char *)data01);
        sprintf((char *)&data01[ldatalen-2],"%02d",msgnumber);
        // bool map_P_Request ( unsigned char * onlyDataNoHeader, int onlyDataNoHeaderLen, gmapid_t gmapid, int packetVersionNumber, int ltxSDU_ID, int sequenceControl0expedited1 )
        insertPacketLenPvnIntoPrimaryHeaderSpot((char *)data01, ldatalen, 0x00); // pvn is 1st 3 bits of octet
        // 
        // map packet v62 m1 variable length
        // 
        // MIB.map_P_Request(data01, ldatalen , GMAPIDv0m0pkt, packetVersionNumber, SDU_ID, seqEx );  // fixed len
        MIB.map_P_Request(data01, ldatalen, GMAPID_62_1varpkt, packetVersionNumber, SDU_ID, seqEx ); // variable length

        // 
        // mapa_sdu v0 m15 fixed length
        // 
        //  bool map_MapaSDU_Request ( unsigned char * onlyDataNoHeader, gmapid_t gmapid, int ltxSDU_ID, int sequenceControl0expedited1)
        sprintf((char *)data01,"HYDROPNEUMATICS%02d",msgnumber);
        ldatalen = strlen((const char *)data01);
        sprintf((char *)&data01[ldatalen-2],"%02d",msgnumber);
        MIB.map_MapaSDU_Request(data01, GMAPIDv0m15mapasdu, SDU_ID, seqEx); // let the managed parameter determine what kinda data it is. only data, no header.

        // 
        // mapa_sdu v62 m14 variable length
        // 
        sprintf((char *)data01,"hydropneumatics%02d",msgnumber);
        ldatalen = strlen((const char *)data01);
        sprintf((char *)&data01[ldatalen-2],"%02d",msgnumber);
        MIB.map_MapaSDU_Request(data01, GMAPID_62_14varsdu, SDU_ID, seqEx ); // let the managed parameter determine what kinda data it is. only data, no header.

        // 
        // octet_stream v7 m8 variable length
        // 
        sprintf((char *)data01,"<octet%02d>",msgnumber);
        // MIB.ocfServiceRequest(ocfdata, GVCID7); // one-off on vcid 7 uncomment to send ocf every frame. leave commented for only first frame tx of ocf
        MIB.map_OctetStream_Request ( data01,  GMAPIDv7m8octTrunc ) ;

        // 
        // truncated v7 m8 variable length
        // 
        sprintf((char *)data01,"<trunc%02d>",msgnumber);
        MIB.map_truncatedFrameRequest ( data01,  GMAPIDv7m8octTrunc ) ;

        // 
        // master channel frame service v14 m7
        // 
        unsigned char mcid_51_frame_service_frame[18] = { 0xc0, 0x03, 0x31, 0xce, 0x00, 0x11, 0x01, 0x00, 0xe3,  'm',  'c',  'i',  'd', 0x00, 0x02,  'f',  's',  '!'}; // tfvn 12, scid 51, vcid 14, mapid 7
        mcid_51_frame_service_frame[7] = msgnumber & 0xff; // set incrementing counter starting at 01
        MIB.masterChannelFrameServiceRequest( mcid_51_frame_service_frame,MCID51); // mc frame service is per physical channel

        // 
        // virtual channel frame service v14 m7
        // 
        unsigned char VCID_frame_service_frame[18] = { 0xc0, 0x02, 0xa6, 0x66, 0x00, 0x11, 0x01, 0x00, 0xe3,  'V',  'C',  'I',  'D', 0x00, 0x02,  'F',  'S',  '!'}; // len 18, tfvn 12, scid 42, vcid 51, mapid 3
        VCID_frame_service_frame[7] = msgnumber & 0xff; // set incrementing counter starting at 01
        MIB.vcFrameServiceRequest (  VCID_frame_service_frame, GVCID51 ); // vcid frame service is per ALREADY VALID MCID

        //
        //
        // different physical channel (fixed len for insert zone) same mcid, vc0, map 0
        //
        //
        sprintf((char *)data01,"#PC2##subdermatoglyphic##");
        ldatalen = strlen((const char*)data01);
        sprintf((char *)&data01[ldatalen-2],"%02d",msgnumber);
        insertPacketLenPvnIntoPrimaryHeaderSpot((char *)data01, ldatalen, 0x00); // pvn is 1st 3 bits of octet
        // seeframe(data01,ldatalen);
        // 
        // map packet v0 m0 fixed len
        // 

        MIB.map_P_Request(data01, ldatalen , G2MAPIDv0m0pkt, packetVersionNumber, SDU_ID, seqEx ); // let the managed parameter determine what kinda data it is. only data, no header.

        sleep(1);
    }
    sleep(40); // let all buffers flush out
    runwhiletrue = 0; // stop the mib thread
    sleep(8);
    printf("main done\n");fflush(stdout);
}
