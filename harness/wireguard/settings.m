// UIKit integration fixture. Real settings controller/localization, stubbed tunnel service.
#import "Shared/WireGuard/SGWGSettingsController.h"
#import "Shared/WireGuard/SGWGCore.h"
#import "Core/SGGlass.h"
#import "../harness-fail.h"

@implementation SGPage
@end
void SGPresentDark(UIViewController *page) { page.overrideUserInterfaceStyle = UIUserInterfaceStyleDark; }
NSString *const SGWGKindWireGuard = @"wireguard", *const SGWGKindHTTP = @"http", *const SGWGKindHTTPS = @"https", *const SGWGKindSOCKS5 = @"socks5";
static BOOL enabled;
BOOL SGWGSettingEnabled(void) { return enabled; }
void SGWGSetSettingEnabled(BOOL value) { enabled = value; }
NSString *SGWGSettingKind(void) { return @"wireguard"; }
NSDictionary *SGWGSettingExternalProxy(void) { return @{}; }
BOOL SGWGHasStoredProxyPassword(void) { return NO; }
BOOL SGWGSaveConnection(NSString *k, NSString *h, NSString *p, NSString *u, NSString *pw, NSString **reason) { return YES; }
NSString *SGWGActiveKind(void) { return @""; }
BOOL SGWGActiveThisLaunch(void) { return NO; }
BOOL SGWGIsSupportedOS(void) { return YES; }
SGWGState SGWGCurrentState(void) { return SGWGStateOff; }
BOOL SGWGHasProfile(void) { return NO; }
NSDictionary *SGWGStoredProfileSummary(void) { return nil; }
BOOL SGWGImportProfile(NSString *text, NSString **reason) { return NO; }
BOOL SGWGDeleteProfile(NSString **reason) { return YES; }
NSDictionary *SGWGEngineStatus(void) { return @{}; }
void SGWGLookupInTunnel(NSString *host, void (^completion)(NSDictionary *)) { completion(@{@"ok":@NO}); }
NSURLSession *SGWGTunnelSession(id<NSURLSessionDelegate> delegate) { return nil; }
NSString *SGWGDiagnosticsReport(NSDictionary *checks) { return @"fixture"; }
NSString *SGWGRedactText(NSString *text) { return text; }
NSArray *SGWGScanTransportClasses(void) { return @[]; }

@interface WGSettingsApp : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end
@implementation WGSettingsApp
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    SGWGSettingsController *page = [SGWGSettingsController new];
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [[UINavigationController alloc] initWithRootViewController:page];
    [self.window makeKeyAndVisible];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        HARNESS_CHECK([page numberOfSectionsInTableView:page.tableView] == 5);
        HARNESS_CHECK([page tableView:page.tableView numberOfRowsInSection:2] == 2);
        HARNESS_CHECK(((UITextField *)[page valueForKey:@"passField"]).secureTextEntry);
        HARNESS_CHECK(page.overrideUserInterfaceStyle == UIUserInterfaceStyleDark);
        // Change modes repeatedly: no constraints left attached to old cells, no hidden profile rows.
        UISegmentedControl *kind = [page valueForKey:@"kindControl"];
        for (NSInteger i=0; i<8; i++) {
            kind.selectedSegmentIndex = i%4;
            [kind sendActionsForControlEvents:UIControlEventValueChanged];
            [page.tableView layoutIfNeeded];
            HARNESS_CHECK([page tableView:page.tableView numberOfRowsInSection:2] == (i%4 ? 0 : 2));
        }
        if (![NSProcessInfo.processInfo.arguments containsObject:@"proxy"]) {
            kind.selectedSegmentIndex = 0;
            [kind sendActionsForControlEvents:UIControlEventValueChanged];
        }
        HARNESS_CHECK([page tableView:page.tableView numberOfRowsInSection:1] == (kind.selectedSegmentIndex ? 5 : 0));
        printf("PASS WireGuard settings: mode changes, secure password, dark style, localized rows\n");
        fflush(stdout);
    });
    return YES;
}
@end
int main(int argc, char **argv) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass(WGSettingsApp.class)); }
}
