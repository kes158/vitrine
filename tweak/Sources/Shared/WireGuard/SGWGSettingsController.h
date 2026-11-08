#import "Settings/SGPage.h"

// Settings, profile import and diagnostics for the app-local WireGuard tunnel.
// Opened from Vitrine settings when the tweak is built with WIREGUARD=1.
@interface SGWGSettingsController : SGPage <UIDocumentPickerDelegate, NSURLSessionDelegate>
@end
