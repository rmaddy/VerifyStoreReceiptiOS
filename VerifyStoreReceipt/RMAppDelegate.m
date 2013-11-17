//
//  RMAppDelegate.m
//  VerifyStoreReceipt
//
//  Created by Rick Maddy on 11/16/13.
//  Copyright (c) 2013 Rick Maddy. All rights reserved.
//

#import "RMAppDelegate.h"
#import "VerifyStoreReceipt.h"
#import <StoreKit/StoreKit.h>

// Per the instructions in VerifyStoreReceipt.m:
// These must be updated with actual values
#warning -- These values should be obfuscated
const NSString * global_bundleVersion = @"1.0.2";
const NSString * global_bundleIdentifier = @"com.example.SampleApp";

@interface RMAppDelegate () <SKRequestDelegate>

@end

@implementation RMAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    [self beginReceiptCheck];
    
    // Empty white screen - there is no UI in this sample app
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor whiteColor];
    [self.window makeKeyAndVisible];

    return YES;
}

- (void)beginReceiptCheck {
    if ([[NSBundle mainBundle] respondsToSelector:@selector(appStoreReceiptURL)]) {
        // See if there is an existing receipt or not
        NSString *appRecPath = [[[NSBundle mainBundle] appStoreReceiptURL] path];
        if ([[NSFileManager defaultManager] fileExistsAtPath:appRecPath]) {
            // There is an existing receipt, see if it is valid.
            [self validateReceipt:appRecPath tryAgain:YES];
        } else {
            // There is no receipt, request one
            [self requestNewReceipt];
        }
    } else {
        // Nothing to do under iOS 6 or earlier. This code requires iOS 7 or later
    }
}

- (void)requestNewReceipt {
    // TODO - this should be updated with the proper use of "Reachability"
    // Begin a request for a receipt from Apple
    SKReceiptRefreshRequest *req = [[SKReceiptRefreshRequest alloc] initWithReceiptProperties:nil];
    req.delegate = self;
    [req start];
}

- (void)validateReceipt:(NSString *)path tryAgain:(BOOL)again {
    // See if the current receipt is valid or not
    BOOL valid = verifyReceiptAtPath(path);
    if (valid) {
        // TODO
        // We have a valid receipt, clear any failures and give the user the full app
        // You may also perform further checks. At this point all we know is that there is a valid receipt.
        //  - You may wish to get details about in-app purchases from the receipt so you can enable just the right
        //    set of in-app purchases in your app.
        //  - You may wish to check when the user purchased the app.
        // See the constants in VerifyStoreReceipt.h for data you can obtain from the receipt:
        // NSDictionary *info = dictionaryWithAppStoreReceipt(path);
        // NSArray *iaps = obtainInAppPurchases(path);
        
        // Note - this may be called on a background thread. Be sure to do any UI work on the main thread
        /*
        dispatch_async(dispatch_get_main_queue(), ^{
            // Any desired UI updates
        });
         */
    } else {
        NSLog(@"Receipt is invalid");
        if (again) {
            // Try one more time to get a valid receipt. This will be reached if the current receipt is stale.
            [self requestNewReceipt];
        } else {
            // TODO
            // Invalid receipt. This probably means your app was cracked. You have various options:
            // 1) Cripple the app in some fashion
            // 2) Terminate the app
            // 3) Alert the user
            // What you do here is up to you and how you wish to handle an invalid receipt
        }
    }
}

- (void)trackFailedAttempt {
    // TODO
    // This will be reached if the code has been unable to obtain a receipt. There are various, legitimate reasons
    // for such problems. But it could also mean the user has a jailbroken device that is deliberately preventing
    // the app from getting a valid receipt.
    // You need to decide how to handle these cases. You can choose to try again later. You can choose to limit how
    // many failed attempts are allowed before treating these failures the same as having an invalid receipt.
    // It's all up to you on what to do here.

    // Note - this may be called on a background thread. Be sure to do any UI work on the main thread
    /*
    dispatch_async(dispatch_get_main_queue(), ^{
         // Any desired UI updates
    });
     */
}

#pragma mark SKRequestDelegate methods

- (void)requestDidFinish:(SKRequest *)request {
    // The request for a receipt completed
    NSString  *appRecPath = [[[NSBundle mainBundle] appStoreReceiptURL] path];
    if ([[NSFileManager defaultManager] fileExistsAtPath:appRecPath]) {
        NSLog(@"Receipt exists");
        
        [self validateReceipt:appRecPath tryAgain:NO];
    } else {
        NSLog(@"Receipt request done but there is no receipt");
        
        // This can happen if the user cancels the login screen for the store.
        // If we get here it means there is no receipt and an attempt to get it failed because the user cancelled
        // the login.
        [self trackFailedAttempt];
    }
}

- (void)request:(SKRequest *)request didFailWithError:(NSError *)error {
    NSLog(@"Error tryung to request receipt: %@", error);
    
    // Unable to get/refresh the receipt
    NSString *appRecPath = [[[NSBundle mainBundle] appStoreReceiptURL] path];
    if ([[NSFileManager defaultManager] fileExistsAtPath:appRecPath]) {
        // There is an existing receipt but we failed to get a new one. This means the existing receipt is invalid
        [self trackFailedAttempt];
    } else {
        // There is no receipt and we were unable to get a new one
        [self trackFailedAttempt];
    }
}

@end
