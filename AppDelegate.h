//
//  AppDelegate.h
//  SM4Crypto
//
//  Created by 戴领 on 2018/4/17.
//  Copyright © 2018年 戴领. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <CoreData/CoreData.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;

@property (readonly, strong) NSPersistentContainer *persistentContainer;

- (void)saveContext;


@end

