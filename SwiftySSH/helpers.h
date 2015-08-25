//
//  helpers.h
//  SwiftySSH
//
//  Created by Solomenchuk, Vlad on 8/20/15.
//  Copyright © 2015 Vladimir Solomenchuk. All rights reserved.
//

#ifndef helpers_h
#define helpers_h

#import "libssh2.h"
extern int waitsocket(int socket_fd, LIBSSH2_SESSION *session);
LIBSSH2_API void *libssh2_session_callback_set_helper(LIBSSH2_SESSION *session,
                                                      int cbtype, void (LIBSSH2_SESSION *session, int reason, const char *message, int message_len, const char *language, int language_len, void **abstract));
#endif /* helpers_h */
