#import "NMSSHChannel.h"
#import "NMSSH+Protected.h"

@interface NMSSHChannel ()
@property (nonatomic, strong) NMSSHSession *session;
@property (nonatomic, assign) LIBSSH2_CHANNEL *channel;

@property (nonatomic, readwrite) NMSSHChannelType type;
@property (nonatomic, assign) const char *ptyTerminalName;
@property (nonatomic, strong) NSString *lastResponse;

#if OS_OBJECT_USE_OBJC
@property (nonatomic, strong) dispatch_source_t source;
#else
@property (nonatomic, assign) dispatch_source_t source;
#endif
@property (nonatomic, strong) NSRecursiveLock *channelLock;
@property (nonatomic, strong) dispatch_queue_t shellEventQueue;
@end

@implementation NMSSHChannel

// -----------------------------------------------------------------------------
#pragma mark - INITIALIZER
// -----------------------------------------------------------------------------

- (instancetype)initWithSession:(NMSSHSession *)session {
    if ((self = [super init])) {
        [self setSession:session];
        [self setBufferSize:kNMSSHBufferSize];
        [self setRequestPty:NO];
        [self setPtyTerminalType:NMSSHChannelPtyTerminalVanilla];
        [self setType:NMSSHChannelTypeClosed];
        _channelLock = [[NSRecursiveLock alloc] init];
        _channelLock.name = @"com.nmssh.channel.lock";
        _shellEventQueue = dispatch_queue_create("com.nmssh.channel.shell", DISPATCH_QUEUE_SERIAL);

        // Make sure we were provided a valid session
        if (![self.session isKindOfClass:[NMSSHSession class]]) {
            @throw @"You have to provide a valid NMSSHSession!";
        }
    }

    return self;
}

- (BOOL)openChannel:(NSError *__autoreleasing *)error {
    [self.channelLock lock];
    @try {
        if (self.channel != NULL) {
            NMSSHLogWarn(@"The channel will be closed before continue");
            if (self.type == NMSSHChannelTypeShell) {
                [self closeShell];
            }
            else {
                [self closeChannel];
            }
        }

        // Set blocking mode
        libssh2_session_set_blocking(self.session.rawSession, 1);

        // Open up the channel
        LIBSSH2_CHANNEL *channel = libssh2_channel_open_session(self.session.rawSession);

        if (channel == NULL){
            NMSSHLogError(@"Unable to open a session");
            if (error) {
                *error = [NSError errorWithDomain:@"NMSSH"
                                             code:NMSSHChannelAllocationError
                                         userInfo:@{ NSLocalizedDescriptionKey : @"Channel allocation error" }];
            }

            return NO;
        }

        [self setChannel:channel];

        // Try to set environment variables
        if (self.environmentVariables) {
            for (NSString *key in self.environmentVariables) {
                if ([key isKindOfClass:[NSString class]] && [[self.environmentVariables objectForKey:key] isKindOfClass:[NSString class]]) {
                    libssh2_channel_setenv(self.channel, [key UTF8String], [[self.environmentVariables objectForKey:key] UTF8String]);
                }
            }
        }

        int rc = 0;

        // If requested, try to allocate a pty
        if (self.requestPty) {
            rc = libssh2_channel_request_pty(self.channel, self.ptyTerminalName);

            if (rc != 0) {
                if (error) {
                    NSDictionary *userInfo = @{ NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Error requesting %s pty: %@", self.ptyTerminalName, [[self.session lastError] localizedDescription]] };

                    *error = [NSError errorWithDomain:@"NMSSH"
                                                 code:NMSSHChannelRequestPtyError
                                             userInfo:userInfo];
                }

                NMSSHLogError(@"Error requesting pseudo terminal");
                [self closeChannel];

                return NO;
            }
        }

        return YES;
    }
    @finally {
        [self.channelLock unlock];
    }
}

- (void)closeChannel {
    LIBSSH2_CHANNEL *channel = NULL;
    LIBSSH2_SESSION *rawSession = self.session.rawSession;

    [self.channelLock lock];
    @try {
        channel = self.channel;
        if (!channel) {
            return;
        }

        [self setChannel:NULL];
        [self setType:NMSSHChannelTypeClosed];
    }
    @finally {
        [self.channelLock unlock];
    }

    if (rawSession) {
        libssh2_session_set_blocking(rawSession, 1);
    }

    int rc = libssh2_channel_close(channel);

    if (rc == 0) {
        libssh2_channel_wait_closed(channel);
    }

    libssh2_channel_free(channel);
}

- (BOOL)sendEOF {
    int rc = LIBSSH2_ERROR_SOCKET_SEND;
    [self.channelLock lock];
    @try {
        if (!self.channel) {
            return NO;
        }
        rc = libssh2_channel_send_eof(self.channel);
    }
    @finally {
        [self.channelLock unlock];
    }

    NMSSHLogVerbose(@"Sent EOF to host (return code = %i)", rc);

    return rc == 0;
}

- (void)waitEOF {
    [self.channelLock lock];
    @try {
        if (self.channel && libssh2_channel_eof(self.channel) == 0) {
            // Wait for host acknowledge
            int rc = libssh2_channel_wait_eof(self.channel);
            NMSSHLogVerbose(@"Received host acknowledge for EOF (return code = %i)", rc);
        }
    }
    @finally {
        [self.channelLock unlock];
    }
}

// -----------------------------------------------------------------------------
#pragma mark - SHELL COMMAND EXECUTION
// -----------------------------------------------------------------------------

- (const char *)ptyTerminalName {
    switch (self.ptyTerminalType) {
        case NMSSHChannelPtyTerminalVanilla:
            return "vanilla";

        case NMSSHChannelPtyTerminalVT100:
            return "vt100";

        case NMSSHChannelPtyTerminalVT102:
            return "vt102";

        case NMSSHChannelPtyTerminalVT220:
            return "vt220";

        case NMSSHChannelPtyTerminalAnsi:
            return "ansi";

        case NMSSHChannelPtyTerminalXterm:
            return "xterm";
    }

    // catch invalid values
    return "vanilla";
}

- (NSString *)execute:(NSString *)command error:(NSError *__autoreleasing *)error {
    return [self execute:command error:error timeout:@0];
}

- (NSString *)execute:(NSString *)command error:(NSError *__autoreleasing *)error timeout:(NSNumber *)timeout {
    NMSSHLogInfo(@"Exec command %@", command);

    // In case of error...
    NSMutableDictionary *userInfo = [NSMutableDictionary dictionaryWithObject:command forKey:@"command"];

    if (![self openChannel:error]) {
        return nil;
    }

    [self setLastResponse:nil];

    int rc = 0;
    [self setType:NMSSHChannelTypeExec];

    // Try executing command
    rc = libssh2_channel_exec(self.channel, [command UTF8String]);

    if (rc != 0) {
        if (error) {
            [userInfo setObject:[[self.session lastError] localizedDescription] forKey:NSLocalizedDescriptionKey];
            [userInfo setObject:[NSString stringWithFormat:@"%i", rc] forKey:NSLocalizedFailureReasonErrorKey];

            *error = [NSError errorWithDomain:@"NMSSH"
                                         code:NMSSHChannelExecutionError
                                     userInfo:userInfo];
        }

        NMSSHLogError(@"Error executing command");
        [self closeChannel];
        return nil;
    }

    // Set non-blocking mode
    libssh2_session_set_blocking(self.session.rawSession, 0);

    // Set the timeout for blocking session
    CFAbsoluteTime time = CFAbsoluteTimeGetCurrent() + [timeout doubleValue];

    // Fetch response from output buffer
    NSMutableString *response = [[NSMutableString alloc] init];
    for (;;) {
        ssize_t rc;
        char buffer[self.bufferSize];
        char errorBuffer[self.bufferSize];

        do {
            rc = libssh2_channel_read(self.channel, buffer, (ssize_t)sizeof(buffer));

            if (rc > 0) {
                [response appendFormat:@"%@", [[NSString alloc] initWithBytes:buffer length:rc encoding:NSUTF8StringEncoding]];
            }

            // Store all errors that might occur
            if (libssh2_channel_get_exit_status(self.channel)) {
                if (error) {
                    ssize_t erc = libssh2_channel_read_stderr(self.channel, errorBuffer, (ssize_t)sizeof(errorBuffer));

                    NSString *desc = [[NSString alloc] initWithBytes:errorBuffer length:erc encoding:NSUTF8StringEncoding];
                    if (!desc) {
                        desc = @"An unspecified error occurred";
                    }

                    [userInfo setObject:desc forKey:NSLocalizedDescriptionKey];
                    [userInfo setObject:[NSString stringWithFormat:@"%zi", erc] forKey:NSLocalizedFailureReasonErrorKey];

                    *error = [NSError errorWithDomain:@"NMSSH"
                                                 code:NMSSHChannelExecutionError
                                             userInfo:userInfo];
                }
            }

            if (libssh2_channel_eof(self.channel) == 1 || rc == 0) {
                while ((rc  = libssh2_channel_read(self.channel, buffer, (ssize_t)sizeof(buffer))) > 0) {
                    [response appendFormat:@"%@", [[NSString alloc] initWithBytes:buffer length:rc encoding:NSUTF8StringEncoding] ];
                }

                [self setLastResponse:[response copy]];
                [self closeChannel];

                return self.lastResponse;
            }

            // Check if the connection timed out
            if ([timeout longValue] > 0 && time < CFAbsoluteTimeGetCurrent()) {
                if (error) {
                    NSString *desc = @"Connection timed out";

                    [userInfo setObject:desc forKey:NSLocalizedDescriptionKey];

                    *error = [NSError errorWithDomain:@"NMSSH"
                                                 code:NMSSHChannelExecutionTimeout
                                             userInfo:userInfo];
                }

                while ((rc  = libssh2_channel_read(self.channel, buffer, (ssize_t)sizeof(buffer))) > 0) {
                    [response appendFormat:@"%@", [[NSString alloc] initWithBytes:buffer length:rc encoding:NSUTF8StringEncoding] ];
                }

                [self setLastResponse:[response copy]];
                [self closeChannel];

                return self.lastResponse;
            }
        } while (rc > 0);

        if (rc != LIBSSH2_ERROR_EAGAIN) {
            break;
        }

        waitsocket(CFSocketGetNative([self.session socket]), self.session.rawSession);
    }

    // If we've got this far, it means fetching execution response failed
    if (error) {
        [userInfo setObject:[[self.session lastError] localizedDescription] forKey:NSLocalizedDescriptionKey];
        *error = [NSError errorWithDomain:@"NMSSH"
                                     code:NMSSHChannelExecutionResponseError
                                 userInfo:userInfo];
    }

    NMSSHLogError(@"Error fetching response from command");
    [self closeChannel];

    return nil;
}

// -----------------------------------------------------------------------------
#pragma mark - REMOTE SHELL SESSION
// -----------------------------------------------------------------------------

- (BOOL)startShell:(NSError *__autoreleasing *)error  {
    NMSSHLogInfo(@"Starting shell");

    if (![self openChannel:error]) {
        return NO;
    }

    // Set non-blocking mode
    libssh2_session_set_blocking(self.session.rawSession, 0);

    // Fetch response from output buffer
#if !(OS_OBJECT_USE_OBJC)
    if (self.source) {
        dispatch_release(self.source);
    }
#endif

    [self setLastResponse:nil];

    dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,
                                                      CFSocketGetNative([self.session socket]),
                                                      0,
                                                      self.shellEventQueue);
    [self setSource:source];

    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(source, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        NMSSHLogVerbose(@"Data available on the socket!");
        char buffer[strongSelf.bufferSize];
        char errorBuffer[strongSelf.bufferSize];

        while (YES) {
            ssize_t rc = 0;
            ssize_t erc = 0;
            NSData *stdoutData = nil;
            NSData *stderrData = nil;
            NSString *responseString = nil;
            BOOL shouldClose = NO;
            BOOL hasData = NO;

            [strongSelf.channelLock lock];
            LIBSSH2_CHANNEL *channel = strongSelf.channel;
            if (!channel) {
                [strongSelf.channelLock unlock];
                return;
            }

            rc = libssh2_channel_read(channel, buffer, (ssize_t)sizeof(buffer));
            erc = libssh2_channel_read_stderr(channel, errorBuffer, (ssize_t)sizeof(errorBuffer));

            if (!(rc >= 0 || erc >= 0)) {
                NMSSHLogVerbose(@"Return code of response %ld, error %ld", (long)rc, (long)erc);

                if (rc == LIBSSH2_ERROR_SOCKET_RECV || erc == LIBSSH2_ERROR_SOCKET_RECV) {
                    NMSSHLogVerbose(@"Error received, closing channel...");
                    shouldClose = YES;
                }
            }

            if (rc > 0) {
                stdoutData = [[NSData alloc] initWithBytes:buffer length:(NSUInteger)rc];
                responseString = [[NSString alloc] initWithData:stdoutData encoding:NSUTF8StringEncoding];
                strongSelf.lastResponse = responseString ? [responseString copy] : nil;
                hasData = YES;
            }

            if (erc > 0) {
                stderrData = [[NSData alloc] initWithBytes:errorBuffer length:(NSUInteger)erc];
                hasData = YES;
            }

            if (!shouldClose && libssh2_channel_eof(channel) == 1) {
                NMSSHLogVerbose(@"Host EOF received, closing channel...");
                shouldClose = YES;
            }

            [strongSelf.channelLock unlock];

            if (stdoutData && responseString && strongSelf.delegate && [strongSelf.delegate respondsToSelector:@selector(channel:didReadData:)]) {
                [strongSelf.delegate channel:strongSelf didReadData:strongSelf.lastResponse];
            }

            if (stdoutData && strongSelf.delegate && [strongSelf.delegate respondsToSelector:@selector(channel:didReadRawData:)]) {
                [strongSelf.delegate channel:strongSelf didReadRawData:stdoutData];
            }

            if (stderrData && strongSelf.delegate && [strongSelf.delegate respondsToSelector:@selector(channel:didReadError:)]) {
                NSString *errorString = [[NSString alloc] initWithData:stderrData encoding:NSUTF8StringEncoding];
                if (errorString) {
                    [strongSelf.delegate channel:strongSelf didReadError:errorString];
                }
            }

            if (stderrData && strongSelf.delegate && [strongSelf.delegate respondsToSelector:@selector(channel:didReadRawError:)]) {
                [strongSelf.delegate channel:strongSelf didReadRawError:stderrData];
            }

            if (shouldClose) {
                [strongSelf closeShell];
                return;
            }

            if (!hasData) {
                break;
            }
        }
    });

    dispatch_source_set_cancel_handler(self.source, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        NMSSHLogVerbose(@"Shell source cancelled");

        if (strongSelf.delegate && [strongSelf.delegate respondsToSelector:@selector(channelShellDidClose:)]) {
            [strongSelf.delegate channelShellDidClose:strongSelf];
        }
    });

    dispatch_resume(source);

    int rc = 0;

    // Try opening the shell
    while (YES) {
        [self.channelLock lock];
        LIBSSH2_CHANNEL *channel = self.channel;
        if (!channel) {
            [self.channelLock unlock];
            rc = LIBSSH2_ERROR_CHANNEL_FAILURE;
            break;
        }

        rc = libssh2_channel_shell(channel);
        [self.channelLock unlock];

        if (rc != LIBSSH2_ERROR_EAGAIN) {
            break;
        }

        waitsocket(CFSocketGetNative([self.session socket]), [self.session rawSession]);
    }

    if (rc != 0) {
        NMSSHLogError(@"Shell request error");
        if (error) {
            *error = [NSError errorWithDomain:@"NMSSH"
                                         code:NMSSHChannelRequestShellError
                                     userInfo:@{ NSLocalizedDescriptionKey : [[self.session lastError] localizedDescription] }];
        }

        [self closeShell];
        return NO;
    }

    NMSSHLogVerbose(@"Shell allocated");
    [self.channelLock lock];
    @try {
        [self setType:NMSSHChannelTypeShell];
    }
    @finally {
        [self.channelLock unlock];
    }

    return YES;
}

- (void)closeShell {
    dispatch_source_t sourceToCancel = nil;
    BOOL wasShell = NO;

    [self.channelLock lock];
    @try {
        sourceToCancel = self.source;
        if (sourceToCancel) {
            [self setSource:nil];
        }

        wasShell = (self.type == NMSSHChannelTypeShell);
    }
    @finally {
        [self.channelLock unlock];
    }

    if (sourceToCancel) {
        dispatch_source_cancel(sourceToCancel);
#if !(OS_OBJECT_USE_OBJC)
        dispatch_release(sourceToCancel);
#endif
    }

    if (wasShell) {
        // Set blocking mode
        libssh2_session_set_blocking(self.session.rawSession, 1);

        [self sendEOF];
    }

    [self closeChannel];
}

- (BOOL)write:(NSString *)command error:(NSError *__autoreleasing *)error {
    return [self write:command error:error timeout:@0];
}

- (BOOL)write:(NSString *)command error:(NSError *__autoreleasing *)error timeout:(NSNumber *)timeout {
    return [self writeData:[command dataUsingEncoding:NSUTF8StringEncoding] error:error timeout:timeout];
}

- (BOOL)writeData:(NSData *)data error:(NSError *__autoreleasing *)error {
    return [self writeData:data error:error timeout:@0];
}

- (BOOL)writeData:(NSData *)data error:(NSError *__autoreleasing *)error timeout:(NSNumber *)timeout {
    BOOL isShell = NO;
    [self.channelLock lock];
    isShell = (self.type == NMSSHChannelTypeShell);
    [self.channelLock unlock];

    if (!isShell) {
        NMSSHLogError(@"Shell required");
        return NO;
    }

    ssize_t rc;

    // Set the timeout
    CFAbsoluteTime time = CFAbsoluteTimeGetCurrent() + [timeout doubleValue];

    // Try writing on shell
    while (YES) {
        [self.channelLock lock];
        LIBSSH2_CHANNEL *channel = self.channel;
        if (!channel) {
            [self.channelLock unlock];
            NMSSHLogError(@"Channel is not available");
            if (error) {
                NSString *description = @"Channel closed";
                *error = [NSError errorWithDomain:@"NMSSH"
                                             code:NMSSHChannelWriteError
                                         userInfo:@{ NSLocalizedDescriptionKey : description }];
            }
            return NO;
        }

        rc = libssh2_channel_write(channel, [data bytes], [data length]);
        [self.channelLock unlock];

        if (rc == LIBSSH2_ERROR_EAGAIN) {
            // Check if the connection timed out
            if ([timeout longValue] > 0 && time < CFAbsoluteTimeGetCurrent()) {
                if (error) {
                    NSString *description = @"Connection timed out";

                    *error = [NSError errorWithDomain:@"NMSSH"
                                                 code:NMSSHChannelExecutionTimeout
                                             userInfo:@{ NSLocalizedDescriptionKey : description }];
                }

                return NO;
            }

            waitsocket(CFSocketGetNative([self.session socket]), self.session.rawSession);
            continue;
        }

        break;
    }

    if (rc < 0) {
        NMSSHLogError(@"Error writing on the shell");
        if (error) {
            NSString *command = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            *error = [NSError errorWithDomain:@"NMSSH"
                                         code:NMSSHChannelWriteError
                                     userInfo:@{ NSLocalizedDescriptionKey : [[self.session lastError] localizedDescription],
                                                 @"command"                : command ?: @"<binary>" }];
        }
        return NO;
    }

    return YES;
}

- (BOOL)requestSizeWidth:(NSUInteger)width height:(NSUInteger)height {
    int rc = LIBSSH2_ERROR_CHANNEL_FAILURE;
    [self.channelLock lock];
    LIBSSH2_CHANNEL *channel = self.channel;
    if (!channel) {
        [self.channelLock unlock];
        NMSSHLogError(@"Channel is not available");
        return NO;
    }
    rc = libssh2_channel_request_pty_size(channel, (int)width, (int)height);
    [self.channelLock unlock];

    if (rc) {
        NMSSHLogError(@"Request size failed with error %i", rc);
    }

    return rc == 0;
}

// -----------------------------------------------------------------------------
#pragma mark - SCP FILE TRANSFER
// -----------------------------------------------------------------------------

- (BOOL)uploadFile:(NSString *)localPath to:(NSString *)remotePath {
    return [self uploadFile:localPath to:remotePath progress:NULL];
}

- (BOOL)uploadFile:(NSString *)localPath to:(NSString *)remotePath progress:(BOOL (^)(NSUInteger))progress {
    if (self.channel != NULL) {
        NMSSHLogWarn(@"The channel will be closed before continue");

        if (self.type == NMSSHChannelTypeShell) {
            [self closeShell];
        }
        else {
            [self closeChannel];
        }
    }

    localPath = [localPath stringByExpandingTildeInPath];

    // Inherit file name if to: contains a directory
    if ([remotePath hasSuffix:@"/"]) {
        remotePath = [remotePath stringByAppendingString:
                      [[localPath componentsSeparatedByString:@"/"] lastObject]];
    }

    // Read local file
    FILE *local = fopen([localPath UTF8String], "rb");
    if (!local) {
        NMSSHLogError(@"Can't read local file");
        return NO;
    }

    // Set blocking mode
    libssh2_session_set_blocking(self.session.rawSession, 1);

    // Try to send a file via SCP.
    struct stat fileinfo;
    stat([localPath UTF8String], &fileinfo);
    LIBSSH2_CHANNEL *channel = libssh2_scp_send64(self.session.rawSession, [remotePath UTF8String], fileinfo.st_mode & 0644,
                                                  (unsigned long)fileinfo.st_size, 0, 0);;

    if (channel == NULL) {
        NMSSHLogError(@"Unable to open SCP session");
        fclose(local);

        return NO;
    }

    [self setChannel:channel];
    [self setType:NMSSHChannelTypeSCP];

    // Wait for file transfer to finish
    char mem[self.bufferSize];
    size_t nread;
    char *ptr;
    long rc;
    NSUInteger total = 0;
    BOOL abort = NO;
    while (!abort && (nread = fread(mem, 1, sizeof(mem), local)) > 0) {
        ptr = mem;

        do {
            // Write the same data over and over, until error or completion
            rc = libssh2_channel_write(self.channel, ptr, nread);

            if (rc < 0) {
                NMSSHLogError(@"Failed writing file");
                [self closeChannel];
                return NO;
            }
            else {
                // rc indicates how many bytes were written this time
                total += rc;
                if (progress && !progress(total)) {
                    abort = YES;
                    break;
                }
                ptr += rc;
                nread -= rc;
            }
        } while (nread);
    };

    fclose(local);

    if ([self sendEOF]) {
        [self waitEOF];
    }
    [self closeChannel];

    return !abort;
}

- (BOOL)downloadFile:(NSString *)remotePath to:(NSString *)localPath {
    return [self downloadFile:remotePath to:localPath progress:NULL];
}

- (BOOL)downloadFile:(NSString *)remotePath to:(NSString *)localPath progress:(BOOL (^)(NSUInteger, NSUInteger))progress {
    if (self.channel != NULL) {
        NMSSHLogWarn(@"The channel will be closed before continue");

        if (self.type == NMSSHChannelTypeShell) {
            [self closeShell];
        }
        else {
            [self closeChannel];
        }
    }

    localPath = [localPath stringByExpandingTildeInPath];

    // Inherit file name if to: contains a directory
    if ([localPath hasSuffix:@"/"]) {
        localPath = [localPath stringByAppendingString:[[remotePath componentsSeparatedByString:@"/"] lastObject]];
    }

    // Set blocking mode
    libssh2_session_set_blocking(self.session.rawSession, 1);

    // Request a file via SCP
    struct stat fileinfo;
    LIBSSH2_CHANNEL *channel = libssh2_scp_recv(self.session.rawSession, [remotePath UTF8String], &fileinfo);

    if (channel == NULL) {
        NMSSHLogError(@"Unable to open SCP session");
        return NO;
    }

    [self setChannel:channel];
    [self setType:NMSSHChannelTypeSCP];

    if ([[NSFileManager defaultManager] fileExistsAtPath:localPath]) {
        NMSSHLogInfo(@"A file already exists at %@, it will be overwritten", localPath);
        [[NSFileManager defaultManager] removeItemAtPath:localPath error:nil];
    }

    // Open local file in order to write to it
    int localFile = open([localPath UTF8String], O_WRONLY|O_CREAT, 0644);

    // Save data to local file
    off_t got = 0;
    while (got < fileinfo.st_size) {
        char mem[self.bufferSize];
        size_t amount = sizeof(mem);

        if ((fileinfo.st_size - got) < amount) {
            amount = (size_t)(fileinfo.st_size - got);
        }

        ssize_t rc = libssh2_channel_read(self.channel, mem, amount);

        if (rc > 0) {
            size_t n = write(localFile, mem, rc);
            if (n < rc) {
                NMSSHLogError(@"Failed to write to local file");
                close(localFile);
                [self closeChannel];
                return NO;
            }
            got += rc;
            if (progress && !progress((NSUInteger)got, (NSUInteger)fileinfo.st_size)) {
                close(localFile);
                [self closeChannel];
                return NO;
            }
        }
        else if (rc < 0) {
            NMSSHLogError(@"Failed to read SCP data");
            close(localFile);
            [self closeChannel];

            return NO;
        }

        memset(mem, 0x0, sizeof(mem));
    }

    close(localFile);
    [self closeChannel];

    return YES;
}

@end

