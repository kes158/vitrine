#import "SGWGSettingsController.h"
#import "SGWGCore.h"
#import <objc/message.h>

#import "Core/SGLocalize.h"
#import "Core/SGGlass.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

typedef NS_ENUM(NSInteger, WGSection) { WGSectionTunnel, WGSectionServer, WGSectionProfile, WGSectionChecks, WGSectionResult, WGSectionCount };
typedef NS_ENUM(NSInteger, WGCheckRow) { WGCheckCountry, WGCheckConnection, WGCheckScan, WGCheckCopy, WGCheckCount };

@interface SGWGSettingsController ()
@property (nonatomic, strong) UISwitch *enabledSwitch;
@property (nonatomic, strong) UISegmentedControl *kindControl;
@property (nonatomic, strong) UITextField *hostField, *portField, *userField, *passField;
@property (nonatomic, copy) NSDictionary *profile;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSString *> *checks;
@property (nonatomic, copy) NSString *resultText;
@property (nonatomic, copy) NSArray<NSString *> *scanLines;
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic) BOOL busy;
@property (nonatomic, strong) NSTimer *statusTimer;
@end

@implementation SGWGSettingsController

- (instancetype)init { return [super initWithStyle:UITableViewStyleInsetGrouped]; }

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self reloadState];
    __weak typeof(self) weakSelf = self;
    self.statusTimer = [NSTimer scheduledTimerWithTimeInterval:1 repeats:YES block:^(NSTimer *timer) {
        typeof(self) self = weakSelf;
        UITableViewCell *cell = [self.tableView cellForRowAtIndexPath:[NSIndexPath indexPathForRow:2 inSection:WGSectionTunnel]];
        cell.detailTextLabel.text = [self stateLine];
    }];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [self.statusTimer invalidate];
    self.statusTimer = nil;
}

- (void)dealloc {
    [self.statusTimer invalidate];
    [self.session invalidateAndCancel];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.overrideUserInterfaceStyle = UIUserInterfaceStyleDark;
    self.title = SGL(@"settings.wireguard.title", @"In-app WireGuard / Proxy");
    self.checks = [NSMutableDictionary dictionary];
    self.enabledSwitch = [UISwitch new];
    [self.enabledSwitch addTarget:self action:@selector(toggleEnabled:) forControlEvents:UIControlEventValueChanged];
    self.kindControl = [[UISegmentedControl alloc] initWithItems:@[@"WireGuard", @"HTTP", @"HTTPS", @"SOCKS5"]];
    [self.kindControl addTarget:self action:@selector(kindChanged) forControlEvents:UIControlEventValueChanged];
    NSDictionary *server = SGWGSettingExternalProxy();
    self.hostField = [self field:@"proxy.example.com" text:server[@"host"]];
    self.portField = [self field:@"8080" text:server[@"port"]];
    self.portField.keyboardType = UIKeyboardTypeNumberPad;
    self.userField = [self field:SGL(@"settings.wireguard.optional", @"optional") text:server[@"username"]];
    self.passField = [self field:SGWGHasStoredProxyPassword() ? SGL(@"settings.wireguard.password_saved", @"saved (leave empty to keep)") : SGL(@"settings.wireguard.optional", @"optional") text:nil];
    self.passField.secureTextEntry = YES;
    self.tableView.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    self.tableView.rowHeight = UITableViewAutomaticDimension;
    self.tableView.estimatedRowHeight = 48;
    [self reloadState];
}

- (UITextField *)field:(NSString *)placeholder text:(NSString *)text {
    UITextField *field = [[UITextField alloc] initWithFrame:CGRectMake(0, 0, 200, 34)];
    field.placeholder = placeholder;
    field.text = text;
    field.textAlignment = NSTextAlignmentRight;
    field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    field.autocorrectionType = UITextAutocorrectionTypeNo;
    field.clearButtonMode = UITextFieldViewModeWhileEditing;
    return field;
}

static NSArray<NSString *> *Kinds(void) { return @[SGWGKindWireGuard, SGWGKindHTTP, SGWGKindHTTPS, SGWGKindSOCKS5]; }

- (NSString *)selectedKind { return Kinds()[MAX(0, self.kindControl.selectedSegmentIndex)]; }
- (BOOL)selectedWireGuard { return [self.selectedKind isEqualToString:SGWGKindWireGuard]; }

- (void)kindChanged {
    [self.view endEditing:YES];
    [self.tableView reloadData];
}

- (void)reloadState {
    NSUInteger index = [Kinds() indexOfObject:SGWGSettingKind()];
    self.kindControl.selectedSegmentIndex = index == NSNotFound ? 0 : (NSInteger)index;
    self.profile = SGWGStoredProfileSummary();
    self.enabledSwitch.on = SGWGSettingEnabled();
    [self.tableView reloadData];
}

#pragma mark - Text

- (NSString *)stateLine {
    SGWGState state = SGWGCurrentState();
    NSString *text;
    switch (state) {
        case SGWGStateOff: text = SGL(@"settings.wireguard.state_off", @"Off in this launch"); break;
        case SGWGStateUnsupported: text = SGL(@"settings.wireguard.state_unsupported", @"Requires iOS 17 or later"); break;
        case SGWGStateWaitingProfile: text = SGL(@"settings.wireguard.state_waiting", @"Waiting for Keychain (unlock the device)"); break;
        case SGWGStateStarting: text = SGL(@"settings.wireguard.state_starting", @"Starting"); break;
        case SGWGStateRunning: text = SGL(@"settings.wireguard.state_running", @"Running"); break;
        case SGWGStateFailed: text = SGL(@"settings.wireguard.state_failed", @"Failed — proxied requests are blocked"); break;
        case SGWGStateExternalProxy: text = [NSString stringWithFormat:SGL(@"settings.wireguard.state_proxy", @"%@ proxy applied"), SGWGActiveKind().uppercaseString]; break;
        case SGWGStateBlocked: text = SGL(@"settings.wireguard.state_blocked", @"Settings unusable — proxied requests are blocked"); break;
    }
    if (state == SGWGStateRunning) {
        NSDictionary *status = SGWGEngineStatus();
        long long age = [status[@"handshakeAgeSec"] longLongValue];
        NSString *handshake = age < 0 ? SGL(@"settings.wireguard.handshake_none", @"no handshake yet")
                                      : [NSString stringWithFormat:SGL(@"settings.wireguard.handshake_ago", @"handshake %lld s ago"), age];
        text = [NSString stringWithFormat:@"%@ · %@", text, handshake];
    }
    BOOL kindChanged = SGWGActiveThisLaunch() && ![SGWGActiveKind() isEqualToString:SGWGSettingKind()];
    if ((SGWGSettingEnabled() != SGWGActiveThisLaunch() || kindChanged) && state != SGWGStateUnsupported)
        text = [text stringByAppendingFormat:@"\n%@", SGL(@"settings.wireguard.restart_needed", @"Restart the app to apply the change")];
    return text;
}

- (NSArray<NSArray<NSString *> *> *)profileRows {
    if (!self.profile) return @[];
    NSDictionary *p = self.profile;
    NSString *extra = [NSString stringWithFormat:@"MTU %@ · Keepalive %@ · PSK %@", p[@"mtu"],
                       [p[@"keepalive"] integerValue] ? p[@"keepalive"] : @"-",
                       [p[@"presharedKey"] boolValue] ? SGL(@"settings.wireguard.yes", @"yes") : SGL(@"settings.wireguard.no", @"no")];
    NSString *endpoint = p[@"endpoint"] ?: @"-";
    if ([p[@"endpointHostname"] boolValue])
        endpoint = [endpoint stringByAppendingFormat:@"\n%@", SGL(@"settings.wireguard.endpoint_dns", @"Host name: looked up once by the device's DNS to reach the server")];
    return @[
        @[SGL(@"settings.wireguard.address", @"Address"), [p[@"addresses"] componentsJoinedByString:@", "] ?: @"-"],
        @[@"DNS", [[p[@"dns"] componentsJoinedByString:@", "] ?: @"-" stringByAppendingFormat:@"\n%@", SGL(@"settings.wireguard.dns_tunnel", @"Queried through the tunnel")]],
        @[SGL(@"settings.wireguard.endpoint", @"Endpoint"), endpoint],
        @[SGL(@"settings.wireguard.options", @"Options"), extra],
    ];
}

#pragma mark - Table

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return WGSectionCount; }

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    switch (section) {
        case WGSectionTunnel: return 3;
        case WGSectionServer:
            if (!self.selectedWireGuard) return 5; // host, port, user, password, save
            return [SGWGSettingKind() isEqualToString:SGWGKindWireGuard] ? 0 : 1; // save
        case WGSectionProfile:
            return self.selectedWireGuard ? (NSInteger)self.profileRows.count + 2 + (self.profile ? 1 : 0) : 0;
        case WGSectionChecks: return WGCheckCount;
        case WGSectionResult: return self.resultText.length ? 1 : 0;
    }
    return 0;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    switch (section) {
        case WGSectionTunnel: return SGL(@"settings.wireguard.section_tunnel", @"Connection");
        case WGSectionServer: return self.selectedWireGuard ? nil : SGL(@"settings.wireguard.section_server", @"Proxy server");
        case WGSectionProfile: return self.selectedWireGuard ? SGL(@"settings.wireguard.section_profile", @"WireGuard profile") : nil;
        case WGSectionChecks: return SGL(@"settings.wireguard.section_checks", @"Checks");
        case WGSectionResult: return self.resultText.length ? SGL(@"settings.wireguard.section_result", @"Result") : nil;
    }
    return nil;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    switch (section) {
        case WGSectionTunnel:
            return SGL(@"settings.wireguard.footer_tunnel", @"Routes Spotify URLSession requests through an in-app WireGuard tunnel or an external proxy. Requires iOS 17. Restart after changes. Other transports, web sign-in and remote playback devices are not covered; this is not a device-wide VPN.");
        case WGSectionServer:
            return self.selectedWireGuard ? nil : SGL(@"settings.wireguard.footer_server", @"HTTP and HTTPS use CONNECT. HTTPS verifies the proxy certificate. Host names are resolved by the proxy. Passwords are kept in the Keychain.");
        case WGSectionProfile:
            if (!self.selectedWireGuard) return nil;
            return SGL(@"settings.wireguard.footer_profile", @"Standard WireGuard .conf with one [Peer] and AllowedIPs 0.0.0.0/0. The private key is stored only in this device's Keychain and is never shown or copied into diagnostics.");
        case WGSectionChecks:
            return SGL(@"settings.wireguard.footer_checks", @"A successful country check does not mean music will play. Also test playback, next track and lock-screen playback, then copy the diagnostics right after any playback error.");
    }
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.numberOfLines = 0;
    cell.detailTextLabel.numberOfLines = 0;
    cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    NSInteger row = indexPath.row;

    if (indexPath.section == WGSectionTunnel) {
        if (row == 0) {
            cell.textLabel.text = SGL(@"settings.wireguard.enable", @"Use this connection in the app");
            cell.accessoryView = self.enabledSwitch;
            self.enabledSwitch.enabled = SGWGIsSupportedOS();
        } else if (row == 1) {
            CGFloat width = MIN(300, self.view.bounds.size.width - 60);
            self.kindControl.frame = CGRectMake(0, 0, width, 32);
            [cell.contentView addSubview:self.kindControl];
            self.kindControl.translatesAutoresizingMaskIntoConstraints = NO;
            [NSLayoutConstraint activateConstraints:@[
                [self.kindControl.centerXAnchor constraintEqualToAnchor:cell.contentView.centerXAnchor],
                [self.kindControl.topAnchor constraintEqualToAnchor:cell.contentView.topAnchor constant:8],
                [self.kindControl.bottomAnchor constraintEqualToAnchor:cell.contentView.bottomAnchor constant:-8],
                [self.kindControl.leadingAnchor constraintEqualToAnchor:cell.contentView.layoutMarginsGuide.leadingAnchor]]];
        } else {
            cell.textLabel.text = SGL(@"settings.wireguard.status", @"Status");
            cell.detailTextLabel.text = [self stateLine];
        }
    } else if (indexPath.section == WGSectionServer) {
        if (self.selectedWireGuard || row == 4) {
            cell.textLabel.text = SGL(@"settings.wireguard.save_connection", @"Save this connection type");
            cell.textLabel.textColor = UIColor.systemBlueColor;
            cell.selectionStyle = UITableViewCellSelectionStyleDefault;
        } else {
            NSArray *labels = @[SGL(@"settings.wireguard.server", @"Server"), SGL(@"settings.wireguard.port", @"Port"), SGL(@"settings.wireguard.username", @"User name"), SGL(@"settings.wireguard.password", @"Password")];
            NSArray *fields = @[self.hostField, self.portField, self.userField, self.passField];
            cell.textLabel.text = labels[row];
            UITextField *field = fields[row];
            field.frame = CGRectMake(0, 0, MIN(220, self.view.bounds.size.width - 150), 34);
            cell.accessoryView = field;
        }
    } else if (indexPath.section == WGSectionProfile) {
        NSArray *rows = self.profileRows;
        if (row < (NSInteger)rows.count) {
            cell.textLabel.text = rows[row][0];
            cell.detailTextLabel.text = rows[row][1];
        } else {
            NSInteger action = row - (NSInteger)rows.count;
            NSArray *titles = @[self.profile ? SGL(@"settings.wireguard.reimport_file", @"Replace from .conf file") : SGL(@"settings.wireguard.import_file", @"Import .conf file"),
                                SGL(@"settings.wireguard.import_pasteboard", @"Import from clipboard"),
                                SGL(@"settings.wireguard.delete_profile", @"Delete profile")];
            cell.textLabel.text = titles[action];
            cell.textLabel.textColor = action == 2 ? UIColor.systemRedColor : UIColor.systemBlueColor;
            cell.selectionStyle = UITableViewCellSelectionStyleDefault;
        }
    } else if (indexPath.section == WGSectionChecks) {
        NSArray *titles = @[SGL(@"settings.wireguard.check_country", @"Check country and exit IP"),
                            SGL(@"settings.wireguard.check_connection", @"Run connection diagnostics (DNS · HTTPS · 206)"),
                            SGL(@"settings.wireguard.check_scan", @"Scan transport classes of this version"),
                            SGL(@"settings.wireguard.check_copy", @"Copy diagnostics")];
        cell.textLabel.text = titles[row];
        cell.textLabel.textColor = self.busy && row < WGCheckCopy ? UIColor.secondaryLabelColor : UIColor.systemBlueColor;
        cell.selectionStyle = UITableViewCellSelectionStyleDefault;
    } else {
        cell.textLabel.text = self.resultText;
        cell.textLabel.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    }
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (indexPath.section == WGSectionServer && (self.selectedWireGuard || indexPath.row == 4)) {
        [self saveConnection];
    } else if (indexPath.section == WGSectionProfile) {
        NSInteger action = indexPath.row - (NSInteger)self.profileRows.count;
        if (action == 0) [self pickFile];
        else if (action == 1) [self importText:UIPasteboard.generalPasteboard.string fromPasteboard:YES];
        else if (action == 2) [self confirmDelete];
    } else if (indexPath.section == WGSectionChecks) {
        if (indexPath.row == WGCheckCopy) [self copyDiagnostics];
        else if (self.busy) return;
        else if (indexPath.row == WGCheckCountry) [self runCountryCheck];
        else if (indexPath.row == WGCheckConnection) [self runConnectionChecks];
        else if (indexPath.row == WGCheckScan) [self runScan];
    }
}

#pragma mark - Settings actions

- (void)alert:(NSString *)title message:(NSString *)message {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:SGL(@"settings.wireguard.ok", @"OK") style:UIAlertActionStyleDefault handler:nil]];
    SGPresentDark(alert);
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)offerRestart {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:SGL(@"settings.wireguard.restart_title", @"Restart required")
        message:SGL(@"settings.wireguard.restart_message", @"Fully close and reopen Spotify to apply this setting.") preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:SGL(@"settings.wireguard.later", @"Later") style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:SGL(@"settings.wireguard.close_now", @"Close app now") style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        SEL suspend = NSSelectorFromString(@"suspend");
        if ([UIApplication.sharedApplication respondsToSelector:suspend])
            ((void (*)(id, SEL))objc_msgSend)(UIApplication.sharedApplication, suspend);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ exit(0); });
    }]];
    SGPresentDark(alert);
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)saveConnection {
    [self.view endEditing:YES];
    NSString *password = self.passField.text.length ? self.passField.text : (self.userField.text.length ? nil : @"");
    NSString *reason = nil;
    if (!SGWGSaveConnection(self.selectedKind, self.hostField.text, self.portField.text, self.userField.text, password, &reason)) {
        [self alert:SGL(@"settings.wireguard.save_failed", @"Could not save") message:reason ?: @""];
        return;
    }
    self.passField.text = nil;
    self.passField.placeholder = SGWGHasStoredProxyPassword() ? SGL(@"settings.wireguard.password_saved", @"saved (leave empty to keep)") : SGL(@"settings.wireguard.optional", @"optional");
    [self reloadState];
    if (SGWGSettingEnabled() || SGWGActiveThisLaunch()) [self offerRestart];
    else [self alert:SGL(@"settings.wireguard.saved", @"Saved") message:SGL(@"settings.wireguard.saved_enable", @"Turn on \"Use this connection in the app\", then restart the app.")];
}

- (void)toggleEnabled:(UISwitch *)sender {
    if (sender.on && !SGWGIsSupportedOS()) {
        sender.on = NO;
        [self alert:SGL(@"settings.wireguard.unsupported_title", @"Not supported") message:SGL(@"settings.wireguard.state_unsupported", @"Requires iOS 17 or later")];
        return;
    }
    BOOL wireguard = [SGWGSettingKind() isEqualToString:SGWGKindWireGuard];
    if (sender.on && !wireguard && ![SGWGSettingExternalProxy()[@"host"] length]) {
        sender.on = NO;
        [self alert:SGL(@"settings.wireguard.no_server_title", @"No proxy server") message:SGL(@"settings.wireguard.no_server", @"Enter the proxy server and tap \"Save this connection type\" first.")];
        return;
    }
    if (sender.on && wireguard && !SGWGHasProfile()) {
        sender.on = NO;
        [self alert:SGL(@"settings.wireguard.no_profile_title", @"No profile") message:SGL(@"settings.wireguard.no_profile", @"Import a WireGuard .conf file first.")];
        return;
    }
    SGWGSetSettingEnabled(sender.on);
    [self reloadState];
    [self offerRestart];
}


#pragma mark - Profile import

- (void)pickFile {
    // Import a sandbox copy, then remove it after putting the profile in Keychain.
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc]
        initForOpeningContentTypes:@[UTTypeData, UTTypeText, UTTypeItem] asCopy:YES];
    picker.delegate = self;
    picker.allowsMultipleSelection = NO;
    SGPresentDark(picker);
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url = urls.firstObject;
    if (!url) return;
    BOOL scoped = [url startAccessingSecurityScopedResource];
    NSFileHandle *file = [NSFileHandle fileHandleForReadingFromURL:url error:nil];
    NSData *data = [file readDataUpToLength:65537 error:nil];
    [file closeAndReturnError:nil];
    if (scoped) [url stopAccessingSecurityScopedResource];
    // The picker's imported copy lives in this app's tmp/Inbox; remove it so the
    // private key exists only in the Keychain.
    NSString *path = url.URLByStandardizingPath.path;
    NSString *sandbox = [NSHomeDirectory() stringByAppendingString:@"/"];
    if ([path hasPrefix:sandbox] && ([path hasPrefix:NSTemporaryDirectory()] || [path containsString:@"/Inbox/"] || [path containsString:@"-Inbox/"]))
        [NSFileManager.defaultManager removeItemAtURL:url error:nil];
    NSString *text = data.length ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
    [self importText:text fromPasteboard:NO];
}

- (void)importText:(NSString *)text fromPasteboard:(BOOL)fromPasteboard {
    if (!text.length || text.length > 65536) {
        [self alert:SGL(@"settings.wireguard.import_failed", @"Could not import") message:SGL(@"settings.wireguard.import_hint", @"Choose a standard WireGuard .conf file (64 KB or smaller).")];
        return;
    }
    NSString *reason = nil;
    if (!SGWGImportProfile(text, &reason)) {
        [self alert:SGL(@"settings.wireguard.import_failed", @"Could not import")
            message:[NSString stringWithFormat:@"%@\n\n%@", SGL(@"settings.wireguard.import_hint", @"Choose a standard WireGuard .conf file (64 KB or smaller)."), reason ?: @""]];
        return;
    }
    // Do not leave the private key on the clipboard. Only touch the pasteboard
    // when the profile came from it (reading it would otherwise prompt).
    if (fromPasteboard) UIPasteboard.generalPasteboard.string = @"";
    [self reloadState];
    if (!SGWGSettingEnabled() && SGWGIsSupportedOS() && [SGWGSettingKind() isEqualToString:SGWGKindWireGuard]) {
        SGWGSetSettingEnabled(YES);
        [self reloadState];
    }
    [self offerRestart];
}

- (void)confirmDelete {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:SGL(@"settings.wireguard.delete_profile", @"Delete profile")
        message:SGL(@"settings.wireguard.delete_message", @"The profile is removed from the Keychain and the tunnel is turned off after restart.") preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:SGL(@"settings.wireguard.cancel", @"Cancel") style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:SGL(@"settings.wireguard.delete", @"Delete") style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        NSString *reason = nil;
        if (!SGWGDeleteProfile(&reason)) [self alert:SGL(@"settings.wireguard.delete_failed", @"Could not delete") message:reason ?: @""];
        [self reloadState];
        [self offerRestart];
    }]];
    SGPresentDark(alert);
    [self presentViewController:alert animated:YES completion:nil];
}

#pragma mark - Checks

- (void)setBusy:(BOOL)busy text:(NSString *)text {
    self.busy = busy;
    if (text) self.resultText = text;
    [self.tableView reloadData];
}

- (BOOL)requireActive {
    if (SGWGActiveThisLaunch()) return YES;
    [self alert:SGL(@"settings.wireguard.not_active_title", @"Tunnel is not active")
        message:SGL(@"settings.wireguard.not_active", @"Turn it on, then fully close and reopen the app. Turn off any system VPN before checking.")];
    return NO;
}

- (void)fetch:(NSString *)urlString range:(NSString *)range completion:(void (^)(NSHTTPURLResponse *response, NSData *data, NSError *error, NSTimeInterval seconds))completion {
    if (!self.session) self.session = SGWGTunnelSession(nil);
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlString]];
    if (range) [request setValue:range forHTTPHeaderField:@"Range"];
    NSDate *start = [NSDate date];
    [[self.session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSTimeInterval seconds = -start.timeIntervalSinceNow;
        dispatch_async(dispatch_get_main_queue(), ^{
            completion([response isKindOfClass:NSHTTPURLResponse.class] ? (NSHTTPURLResponse *)response : nil, data, error, seconds);
        });
    }] resume];
}

static NSString *ErrorText(NSError *error) {
    return error ? [NSString stringWithFormat:@"%@ %ld", error.domain, (long)error.code] : @"";
}

- (void)runCountryCheck {
    if (![self requireActive]) return;
    [self setBusy:YES text:SGL(@"settings.wireguard.checking", @"Checking through the tunnel…")];
    [self fetch:@"https://www.cloudflare.com/cdn-cgi/trace" range:nil completion:^(NSHTTPURLResponse *response, NSData *data, NSError *error, NSTimeInterval seconds) {
        NSString *ip = nil, *loc = nil;
        NSString *body = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
        for (NSString *line in [body componentsSeparatedByString:@"\n"]) {
            if ([line hasPrefix:@"ip="]) ip = [line substringFromIndex:3];
            if ([line hasPrefix:@"loc="]) loc = [line substringFromIndex:4];
        }
        NSString *text;
        if (error || response.statusCode != 200 || !ip.length || !loc.length) {
            text = [NSString stringWithFormat:@"%@\n%@ HTTP %ld", SGL(@"settings.wireguard.country_failed", @"Country check failed."), ErrorText(error), (long)response.statusCode];
            self.checks[@"country"] = [NSString stringWithFormat:@"failed %@ HTTP %ld", ErrorText(error), (long)response.statusCode];
        } else {
            text = [NSString stringWithFormat:SGL(@"settings.wireguard.country_result", @"Country: %@\nExit IP: %@\n\nThis only proves the tunnel works. Now play a song, skip to the next one and try lock-screen playback."), loc, ip];
            self.checks[@"country"] = [NSString stringWithFormat:@"%@ exit %@ (%.1f s)", loc, ip, seconds];
        }
        [self setBusy:NO text:text];
    }];
}

- (void)runConnectionChecks {
    if (![self requireActive]) return;
    [self setBusy:YES text:SGL(@"settings.wireguard.checking", @"Checking through the tunnel…")];
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    if (![SGWGActiveKind() isEqualToString:SGWGKindWireGuard]) {
        // External proxy: URLSession sends host names to the proxy (CONNECT / SOCKS5).
        [lines addObject:SGL(@"settings.wireguard.dns_by_proxy", @"DNS: resolved by the proxy server")];
        self.checks[@"dns"] = @"resolved by external proxy";
        [self checkHTTPS:lines];
        return;
    }
    // Lookups use the profile's DNS servers through the tunnel (Go netstack).
    NSArray<NSString *> *hosts = @[@"apresolve.spotify.com", @"spclient.wg.spotify.com", @"audio-fa.scdn.co"];
    __block NSUInteger pending = hosts.count;
    for (NSString *host in hosts) {
        SGWGLookupInTunnel(host, ^(NSDictionary *result) {
            BOOL ok = [result[@"ok"] boolValue];
            [lines addObject:ok ? [NSString stringWithFormat:@"DNS (tunnel) %@: OK %@ addr, %@ ms", host, result[@"count"], result[@"ms"]]
                                : [NSString stringWithFormat:@"DNS (tunnel) %@: FAIL %@", host, result[@"error"] ?: @"failed"]];
            self.checks[[@"dns." stringByAppendingString:host]] = ok ? [NSString stringWithFormat:@"ok %@ addr %@ ms", result[@"count"], result[@"ms"]]
                                                                      : [NSString stringWithFormat:@"failed %@", result[@"error"]];
            if (--pending == 0) [self checkHTTPS:lines];
        });
    }
}

- (void)checkHTTPS:(NSMutableArray<NSString *> *)lines {
    [self fetch:@"https://www.google.com/generate_204" range:nil completion:^(NSHTTPURLResponse *response, NSData *data, NSError *error, NSTimeInterval seconds) {
        BOOL ok = !error && response.statusCode == 204;
        [lines addObject:[NSString stringWithFormat:@"HTTPS www.google.com: %@ HTTP %ld %@ (%.1f s)", ok ? @"OK" : @"FAIL", (long)response.statusCode, ErrorText(error), seconds]];
        self.checks[@"https.generate_204"] = [NSString stringWithFormat:@"HTTP %ld %@ %.1fs", (long)response.statusCode, ErrorText(error), seconds];
        [self checkRange:@[@"https://www.gstatic.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png",
                           @"https://raw.githubusercontent.com/kes158/vitrine/main/LICENSE"] index:0 lines:lines];
    }];
}

// A byte-range request like the music loader's. A server that ignores Range
// (HTTP 200) is not counted as success; the next candidate is tried.
- (void)checkRange:(NSArray<NSString *> *)candidates index:(NSUInteger)index lines:(NSMutableArray<NSString *> *)lines {
    if (index >= candidates.count) {
        [lines addObject:@"HTTP 206: FAIL no candidate returned partial content"];
        self.checks[@"range206"] = @"no candidate returned 206";
        [self finishChecks:lines];
        return;
    }
    [self fetch:candidates[index] range:@"bytes=0-1023" completion:^(NSHTTPURLResponse *response, NSData *data, NSError *error, NSTimeInterval seconds) {
        NSString *contentRange = response.allHeaderFields[@"Content-Range"];
        NSString *host = [NSURL URLWithString:candidates[index]].host;
        if (!error && response.statusCode == 206 && data.length == 1024 && [contentRange hasPrefix:@"bytes 0-1023/"]) {
            [lines addObject:[NSString stringWithFormat:@"HTTP 206: OK %@ (%lu B, %.1f s)", host, (unsigned long)data.length, seconds]];
            self.checks[@"range206"] = [NSString stringWithFormat:@"206 ok host=%@ %.1fs", host, seconds];
            [self finishChecks:lines];
        } else {
            [lines addObject:[NSString stringWithFormat:@"HTTP 206: %@ HTTP %ld %@", host, (long)response.statusCode, ErrorText(error)]];
            [self checkRange:candidates index:index + 1 lines:lines];
        }
    }];
}

- (void)finishChecks:(NSMutableArray<NSString *> *)lines {
    [lines addObject:@""];
    [lines addObject:SGL(@"settings.wireguard.checks_note", @"These checks do not prove music playback. Test real playback too.")];
    [self setBusy:NO text:[lines componentsJoinedByString:@"\n"]];
}

- (void)runScan {
    [self setBusy:YES text:SGL(@"settings.wireguard.scanning", @"Scanning…")];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSArray *lines = SGWGScanTransportClasses();
        dispatch_async(dispatch_get_main_queue(), ^{
            self.scanLines = lines;
            [self setBusy:NO text:[lines componentsJoinedByString:@"\n\n"]];
        });
    });
}

- (void)copyDiagnostics {
    NSString *report = SGWGDiagnosticsReport(self.checks);
    if (self.scanLines.count)
        report = [report stringByAppendingFormat:@"\n%@", SGWGRedactText([self.scanLines componentsJoinedByString:@"\n"])];
    UIPasteboard.generalPasteboard.string = report;
    self.resultText = report;
    [self.tableView reloadData];
    [self alert:SGL(@"settings.wireguard.copied_title", @"Diagnostics copied")
        message:SGL(@"settings.wireguard.copied", @"Only counters, HTTP status codes and error codes were copied. Keys, tokens, song URLs and full IP addresses are removed.")];
}

@end
