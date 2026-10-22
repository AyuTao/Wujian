import Foundation
import NetworkExtension
import GuardCore

@objc(WujianPacketFilterProvider)
final class PacketFilterProvider: NEFilterPacketProvider {
    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let gate: PacketGate?
        do {
            guard let url = Bundle.main.url(forResource: "country-cn", withExtension: "txt") else { throw GuardDataError.invalidDatabase }
            let text = try String(contentsOf: url, encoding: .utf8)
            gate = try PacketGate(cnCIDRs: text, disablePublicIPv6: true)
            NSLog("Wujian packet filter loaded %d CN networks", gate!.networkCount)
        } catch {
            gate = nil
            // A corrupted/missing table never becomes "allow all". This fault
            // must be diagnosed through local logs/OS settings, not IP traffic.
            NSLog("Wujian GeoIP table unavailable; all IP packets will be dropped")
        }
        packetHandler = { _, _, direction, bytes, length in
            guard let gate else { return .drop }
            guard direction == .outbound || direction == .inbound else { return .drop }
            let decision = gate.evaluate(UnsafeRawBufferPointer(start: bytes, count: length), outbound: direction == .outbound)
            return decision == .allow ? .allow : .drop
        }
        completionHandler(nil)
    }
    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        packetHandler = nil
        completionHandler()
    }
}
