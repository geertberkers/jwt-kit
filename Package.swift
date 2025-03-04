// swift-tools-version:5.2
import PackageDescription

let package = Package(
    name: "jwt-kit",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
    ],
    products: [
        .library(name: "JWTKit", targets: ["JWTKit"]),
        /* This target is used only for symbol mangling. It's added and removed automatically because it emits build warnings. MANGLE_START
        .library(name: "CJWTKitBoringSSL", type: .static, targets: ["CJWTKitBoringSSL"]),
        MANGLE_END */
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "1.0.0"),
        .package(url: "https://github.com/IBM-Swift/LoggerAPI.git", from: "1.7.3"),

    ],
    targets: [
        .target(name: "CJWTKitBoringSSL"),
        .target(name: "JWTKit", dependencies: [
            "LoggerAPI",
            .target(name: "CJWTKitBoringSSL"),
            .product(name: "Crypto", package: "swift-crypto"),
        ]),
        .testTarget(name: "JWTKitTests", dependencies: [
            .target(name: "JWTKit"),
        ]),
    ],
     cxxLanguageStandard: .cxx11
)
