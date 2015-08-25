//
//  helpers.c
//  SwiftySSH
//
//  Created by Solomenchuk, Vlad on 8/20/15.
//  Copyright © 2015 Vladimir Solomenchuk. All rights reserved.
//

#import "helpers.h"
#import <arpa/inet.h>
#import <sys/select.h>

inline LIBSSH2_API void *libssh2_session_callback_set_helper(LIBSSH2_SESSION *session,
                                                             int cbtype, void(*callback) (LIBSSH2_SESSION *session, int reason, const char *message, int message_len, const char *language, int language_len, void **abstract)){
    return libssh2_session_callback_set(session, cbtype, callback);
}


int waitsocket(int socket_fd, LIBSSH2_SESSION *session) {
    struct timeval timeout;
    
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    
    int rc;
    int dir;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    
    FD_ZERO(&fd);
    FD_SET(socket_fd, &fd);
    
    // Now make sure we wait in the correct direction
    dir = libssh2_session_block_directions(session);
    
    if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
        readfd = &fd;
    }
    
    if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
        writefd = &fd;
    }
    
    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);
    
    return rc;
}