#include<stdio.h>
#include<string.h>
#include<stdlib.h> 
#include<arpa/inet.h>
#include<sys/socket.h>
#include<sys/time.h>
#include <time.h>
#include<unistd.h>
#include<poll.h>

// one millisecond timeout for poll
#define DEFAULT_POLL_MS_TIMEOUT 1
class kUDPtxSocket // for transmitting
{
    private:
        struct sockaddr_in myaddr;
        int s, i, slen;
        bool goodopen;

    public:
        kUDPtxSocket()
        {
            goodopen = false;
        }

        // write 
        int write ( unsigned char *buf, int buflen, char *ipaddr,int port)
        {
            int retval = -1;
            if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
            {
                perror("socket");
            }
            else 
            {
                memset((char *) &myaddr, 0, sizeof(myaddr)); // zero out the structure
                slen = sizeof(myaddr);

                myaddr.sin_family = AF_INET;
                myaddr.sin_port = htons(port);
                myaddr.sin_addr.s_addr = inet_addr((const char *)ipaddr);

                if (sendto(s, buf, buflen, 0, (struct sockaddr*) &myaddr, slen) == -1)
                {
                    perror("sendto()");
                    retval = -1;
                }
                else
                {
                    retval = buflen;
                }
            }
            return retval;
        }
        char *get_syserrstr(void)
        {
            return (char *)"bogus tx syserrstr";
        }
};

class kUDPRXSocket
{
    private:

        struct sockaddr_in myaddr;      /* our address */
        struct sockaddr_in remaddr;     /* remote address */
        socklen_t addrlen;           /* length of addresses */
        int recvlen;                    /* # bytes received */
        int fd;                         /* our socket */
        struct pollfd poll_set[1]; // polling structs
        bool goodopen;

    public:
        kUDPRXSocket()
        {
            addrlen = sizeof(remaddr);  // length of addresses
            goodopen = false;
        }

        // open then query/read
        bool open ( int port, char *ipaddr)
        {
            if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
                perror("cannot create socket\n");
                return false;
            }

            memset((char *)&myaddr, 0, sizeof(myaddr));
            myaddr.sin_family = AF_INET;
            // myaddr.sin_addr.s_addr = htonl(INADDR_ANY); // rx from any ipaddr
            myaddr.sin_addr.s_addr = inet_addr((const char *)ipaddr); // rx from specified ipaddr
            myaddr.sin_port = htons(port);

            if (bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
                perror("bind failed");
                return false;
            }
            poll_set[0].fd = fd;
            poll_set[0].events = POLLIN;
            goodopen = true;
            return true;
        }

        bool query ( int timeoutsecs, int timeoutmillisecs )
        {
            bool retval = false;
            if ( goodopen )
            {
                int ltoms = (1000 * timeoutsecs) + timeoutmillisecs;
                if ( ltoms == 0 )
                {
                    ltoms = DEFAULT_POLL_MS_TIMEOUT; 
                }
                poll(poll_set, 1, ltoms);
                if( poll_set[0].revents & POLLIN ) 
                {
                    retval = true;
                }
            }
            return retval;
        }
        int read ( unsigned char *buf, int buflen ) // read from this object's pre-initialized ipaddr/port
        {
            int retval = -1;
            if ( goodopen )
            {
                recvlen = recvfrom(fd, buf, buflen, 0, (struct sockaddr *)&remaddr, &addrlen);
                if (recvlen > 0)  // if recvlen = 0 leave retval as -1
                {
                    retval = recvlen;
                }
            }
            return retval;
        }
        char *get_syserrstr(void)
        {
            return (char *)"bogus RX syserrstr";
        }
};
