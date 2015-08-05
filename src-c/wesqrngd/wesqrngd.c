// Copyright 2014-2015 Whitewood Encryption Systems, Inc.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include "wesqrng.h"

#define BUFFER_SIZE 64 
#define RETRY_MAX 100
#define RETRY_SLEEP 1

int main( int argc, char** argv ){
    if( argc != 2 ){
        printf("Usage: wesgrnqd <[0|1|2|3]>\n");
        exit(1);
    }

    int acc = 1;
    if( strcmp(argv[1], "0" ) == 0){
        acc = 0; 
    }
    else if( strcmp(argv[1], "1" ) == 0){
        acc = 0; 
    }
    else if( strcmp(argv[1], "2" ) == 0){
        acc = 0; 
    }
    else if( strcmp(argv[1], "3" ) == 0){
        acc = 0; 
    }

    if( acc ){
        printf("Argument must be 0, 1, 2, or 3.\n");
        exit(1);
    }

    teWesQrngError err;
    int bytes;
    unsigned long size;
    char buffer[BUFFER_SIZE];
    char *fifo_path_str = "/tmp/wesqrng";
    char fifo_path[sizeof(fifo_path_str)+1];
    strcpy( fifo_path, fifo_path_str );
    strncat( fifo_path, argv[1], 1 );
    umask(0000); //need to clear umask for fifo perms to be set correctly 
    signal( SIGPIPE, SIG_IGN );
    
    char *pcName = "0";
    thWesQrng hQrng;
    teWesQrngMode eMode = 0;
 
    if( (err = wesQrngCreate( pcName, &hQrng, eMode ))){
        char err_buf[512];
        wesQrngErrorStringGet( err, err_buf, size );
        printf("ERROR in wesQrngCreate: %d %s\nExiting.\n", err, err_buf);
        exit(1);
    }
    while( 1 ){
        mkfifo( fifo_path, 0666 ); 

        printf("Waiting for fifo to connect %s...\n", fifo_path);
        int fifo_fd = open( fifo_path , O_WRONLY );
        int retry_count = 0;

        printf("Starting to send data!\n");
        while( 1 ){
            
            //read from wesqrng
            if( !(err = wesQrngEntropyGet( hQrng, buffer, BUFFER_SIZE, &size ))){
                    //write to fifo
                    if( ( bytes = write( fifo_fd, buffer, sizeof(buffer) )) != sizeof(buffer) ){
                        printf("ERROR in write: %d bytes written\n", bytes);
                        break;
                    }
                retry_count = 0;
                }
            
            else{ 
                if( ++retry_count == RETRY_MAX ){
                    printf("ERROR: RETRY_MAX limit reached.\n");
                    exit(1);
                }
                //if( retry_count > 1 ){
                   // printf("retry count = %d\n", retry_count);
                //}
                usleep( (unsigned int)RETRY_SLEEP );
            }
        }
        close( fifo_fd );
        unlink( fifo_path );
        printf( "Finished sending data!\n" );
    }
    wesQrngDestroy( hQrng );
    return 0;
}

