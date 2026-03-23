// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "GuardSDK",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "GuardSDK", targets: ["GuardSDK"]),
    ],
    targets: [
        .target(
            name: "GuardSDK",
            path: "Sources/GuardSDK",
            cSettings: [
                .headerSearchPath("Native/include"),
            ]
        ),
        .testTarget(
            name: "GuardSDKTests",
            dependencies: ["GuardSDK"],
            path: "Tests"
        ),
    ]
)
