// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "WujianGuardCore",
    platforms: [.macOS(.v14)],
    products: [.library(name: "GuardCore", type: .static, targets: ["GuardCore"])],
    targets: [.target(name: "GuardCore"), .testTarget(name: "GuardCoreTests", dependencies: ["GuardCore"]) ]
)
