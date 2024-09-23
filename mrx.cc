#include<stdio.h>
#include <map>
#include"mib.cc"
extern char	klmglobalFrameType[];
extern char klmReadFromThisFile[];
mibclass MIB;
int main(int argc, char *argv[])
{
    gvcid GVCID;
    char *configfile = (char *)"./mibconfig";
    if ( argc > 1 )
    {
        configfile = argv[1]; // ur configfile
    }
    /*
       not sure frame type is needed in rx
       if ( argc > 2 )
       {
       strcpy(klmglobalFrameType,argv[2]); // ur configfile fixed
       }
       */
    if ( argc > 2 )
    {
        strcpy(klmReadFromThisFile,argv[2]); // ur configfile fixed framefile
    }
    MIB.readMibConfig(configfile);

    // security header/trailer must match on both sides
    GVCID.set("PC2",12,42,0);
    MIB.putSecurityHeader((unsigned char *)"<schd>",GVCID);
    MIB.putSecurityTrailer((unsigned char *)"<sctrLR>",GVCID);

    //MIB.dumpConfigs();

    MIB.rx(); //stays here and receives
}
