import Foundation
import Darwin

private struct TrieNode: Sendable { var zero = -1; var one = -1; var terminal = false }

/// Immutable prefix trie. Lookup is bounded by 32/128 bits, not database size.
private struct PrefixTrie: Sendable {
    var nodes = [TrieNode()]
    mutating func insert(_ bytes: [UInt8], prefix: Int) {
        var node = 0
        for bit in 0..<prefix {
            let one = bytes[bit / 8] & (0x80 >> (bit % 8)) != 0
            var child = one ? nodes[node].one : nodes[node].zero
            if child == -1 {
                child = nodes.count; nodes.append(TrieNode())
                if one { nodes[node].one = child } else { nodes[node].zero = child }
            }
            node = child
        }
        nodes[node].terminal = true
    }
    func contains(_ bytes: [UInt8]) -> Bool {
        var node = 0
        for bit in 0..<(bytes.count * 8) {
            if nodes[node].terminal { return true }
            let one = bytes[bit / 8] & (0x80 >> (bit % 8)) != 0
            node = one ? nodes[node].one : nodes[node].zero
            if node == -1 { return false }
        }
        return nodes[node].terminal
    }
}

public enum GuardDataError: Error { case invalidCIDR, invalidDatabase }
public enum PacketDecision: Sendable, Equatable { case allow, drop }

/// Restricted-mode packet executor. It does not grant an "environment safe"
/// verdict. Disabling the filter is a separate explicit user operation.
public struct PacketGate: Sendable {
    private var ipv4 = PrefixTrie()
    private var ipv6 = PrefixTrie()
    private let disablePublicIPv6: Bool
    public private(set) var networkCount = 0

    public init(cnCIDRs: String, disablePublicIPv6: Bool = true) throws {
        self.disablePublicIPv6 = disablePublicIPv6
        guard cnCIDRs.utf8.count <= 16 * 1024 * 1024 else { throw GuardDataError.invalidDatabase }
        for rawLine in cnCIDRs.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") { continue }
            guard networkCount < 200_000 else { throw GuardDataError.invalidDatabase }
            let parts = line.split(separator: "/", omittingEmptySubsequences: false)
            guard parts.count == 2, let prefix = Int(parts[1]) else { throw GuardDataError.invalidCIDR }
            let isV6 = parts[0].contains(":")
            let count = isV6 ? 16 : 4
            guard prefix >= (isV6 ? 16 : 8), prefix <= count * 8 else { throw GuardDataError.invalidCIDR }
            var bytes = [UInt8](repeating: 0, count: count)
            let valid = bytes.withUnsafeMutableBytes { p in String(parts[0]).withCString { inet_pton(isV6 ? AF_INET6 : AF_INET, $0, p.baseAddress!) } }
            guard valid == 1 else { throw GuardDataError.invalidCIDR }
            for bit in prefix..<(count * 8) where bytes[bit / 8] & (0x80 >> (bit % 8)) != 0 { throw GuardDataError.invalidCIDR }
            if isV6 { ipv6.insert(bytes, prefix: prefix) } else { ipv4.insert(bytes, prefix: prefix) }
            networkCount += 1
        }
        guard networkCount > 0 else { throw GuardDataError.invalidDatabase }
    }

    public func evaluate(_ data: Data, outbound: Bool) -> PacketDecision {
        data.withUnsafeBytes { evaluate($0, outbound: outbound) }
    }
    public func evaluate(_ packet: UnsafeRawBufferPointer, outbound: Bool) -> PacketDecision {
        guard packet.count > 0 else { return .drop }
        let version = packet[0] >> 4
        if version == 4 {
            guard packet.count >= 20 else { return .drop }
            let headerLength = Int(packet[0] & 15) * 4
            let total = Int(packet[2]) * 256 + Int(packet[3])
            guard headerLength >= 20, headerLength <= packet.count, total >= headerLength, total <= packet.count else { return .drop }
            let offset = outbound ? 16 : 12
            let address = Array(packet[offset..<(offset + 4)])
            if Self.localIPv4(address) { return .allow }
            return ipv4.contains(address) ? .allow : .drop
        }
        if version == 6 {
            guard packet.count >= 40 else { return .drop }
            let payload = Int(packet[4]) * 256 + Int(packet[5])
            guard payload + 40 <= packet.count else { return .drop }
            let offset = outbound ? 24 : 8
            let address = Array(packet[offset..<(offset + 16)])
            if Self.localIPv6(address) { return .allow }
            // Treat IPv4-mapped addresses as IPv4, including the local ranges.
            if address.prefix(10).allSatisfy({ $0 == 0 }) && address[10] == 255 && address[11] == 255 {
                let v4 = Array(address.suffix(4))
                if Self.localIPv4(v4) { return .allow }
                return disablePublicIPv6 ? .drop : (ipv4.contains(v4) ? .allow : .drop)
            }
            if disablePublicIPv6 { return .drop }
            return ipv6.contains(address) ? .allow : .drop
        }
        return .drop
    }
    private static func localIPv4(_ b: [UInt8]) -> Bool {
        b[0] == 127 || b[0] == 10 || (b[0] == 172 && (16...31).contains(b[1])) ||
        (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) ||
        (b[0] == 100 && (64...127).contains(b[1])) ||
        (b[0] == 224 && b[1] == 0 && b[2] == 0) || b.allSatisfy({ $0 == 255 })
    }
    private static func localIPv6(_ b: [UInt8]) -> Bool {
        (b.prefix(15).allSatisfy({ $0 == 0 }) && b[15] == 1) ||
        (b[0] == 0xfe && b[1] & 0xc0 == 0x80) || b[0] & 0xfe == 0xfc ||
        (b[0] == 0xff && b[1] & 0x0f == 2)
    }
}
