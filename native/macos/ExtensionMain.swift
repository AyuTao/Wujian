import NetworkExtension
import Foundation

@main struct ExtensionMain {
    static func main() {
        NEProvider.startSystemExtensionMode()
        dispatchMain()
    }
}
