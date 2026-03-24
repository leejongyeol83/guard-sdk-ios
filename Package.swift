// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "guard-sdk-ios",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "GuardSDK", targets: ["GuardSDK"]),
    ],
    targets: [
        .target(
            name: "GuardNative",
            path: "Sources/GuardNative",
            publicHeadersPath: "include"
        ),
        .target(
            name: "GuardSDK",
            dependencies: ["GuardNative"],
            path: "Sources/GuardSDK"
        ),
        .testTarget(
            name: "GuardSDKTests",
            dependencies: ["GuardSDK"],
            path: "Tests"
        ),
    ]
)
