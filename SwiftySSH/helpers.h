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
#endif /* helpers_h */
