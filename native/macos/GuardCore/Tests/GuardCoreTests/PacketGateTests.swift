import XCTest
import Darwin
@testable import GuardCore

final class PacketGateTests: XCTestCase {
    let table = "1.0.1.0/24\n223.5.5.0/24\n2400:3200::/32\n"
    func v4(_ remote: [UInt8], outbound: Bool = true, proto: UInt8 = 6) -> Data {
        var p = [UInt8](repeating: 0, count: 40); p[0] = 0x45; p[3] = 40; p[9] = proto
        p.replaceSubrange(12..<16, with: outbound ? [192,168,1,2] : remote)
        p.replaceSubrange(16..<20, with: outbound ? remote : [192,168,1,2]); return Data(p)
    }
    func v6(_ text: String, outbound: Bool = true) -> Data {
        var p = [UInt8](repeating: 0, count: 40); p[0] = 0x60
        var addr = [UInt8](repeating: 0, count: 16)
        addr.withUnsafeMutableBytes { ptr in text.withCString { _ = inet_pton(AF_INET6,$0,ptr.baseAddress!) } }
        p.replaceSubrange(outbound ? 24..<40 : 8..<24, with: addr); return Data(p)
    }
    func testChinaPassesForeignAndUnknownDropForTCPAndUDP() throws {
        let gate = try PacketGate(cnCIDRs: table)
        for proto: UInt8 in [6,17] {
            XCTAssertEqual(gate.evaluate(v4([223,5,5,5],proto:proto),outbound:true),.allow)
            XCTAssertEqual(gate.evaluate(v4([8,8,8,8],proto:proto),outbound:true),.drop)
            XCTAssertEqual(gate.evaluate(v4([203,0,113,10],proto:proto),outbound:true),.drop)
        }
    }
    func testInboundRepliesAndAlreadyEstablishedPacketsDoNotBypassDecision() throws {
        let gate = try PacketGate(cnCIDRs: table)
        XCTAssertEqual(gate.evaluate(v4([8,8,8,8],outbound:false),outbound:false),.drop)
        var established = v4([8,8,8,8]); established[33] = 0x10 // TCP ACK, no SYN
        XCTAssertEqual(gate.evaluate(established,outbound:true),.drop)
    }
    func testLocalAndTailscaleAddressesRemainAvailable() throws {
        let gate = try PacketGate(cnCIDRs: table)
        for ip: [UInt8] in [[127,0,0,1],[192,168,10,1],[100,100,100,100],[10,0,0,1],[169,254,1,1]] { XCTAssertEqual(gate.evaluate(v4(ip),outbound:true),.allow) }
        for ip in ["::1","fe80::1","fd7a:115c:a1e0::53","ff02::1"] { XCTAssertEqual(gate.evaluate(v6(ip),outbound:true),.allow) }
    }
    func testPublicIPv6IsBlockedByDefaultIncludingChinaAndMappedAddresses() throws {
        let gate = try PacketGate(cnCIDRs: table)
        for ip in ["2400:3200::1","2001:4860:4860::8888","::ffff:8.8.8.8"] { XCTAssertEqual(gate.evaluate(v6(ip),outbound:true),.drop) }
        let v6Allowed = try PacketGate(cnCIDRs: table,disablePublicIPv6:false)
        XCTAssertEqual(v6Allowed.evaluate(v6("2400:3200::1"),outbound:true),.allow)
        XCTAssertEqual(v6Allowed.evaluate(v6("2001:4860:4860::8888"),outbound:true),.drop)
    }
    func testMalformedPacketsFailClosed() throws {
        let gate = try PacketGate(cnCIDRs: table)
        for p in [Data(),Data([0x45]),Data(repeating:0,count:40),Data([0x60,0,0])] { XCTAssertEqual(gate.evaluate(p,outbound:true),.drop) }
        var p=v4([223,5,5,5]);p[0]=0x4f;XCTAssertEqual(gate.evaluate(p,outbound:true),.drop)
    }
    func testEmptyBroadMalformedAndNonCanonicalTablesAreRejected() {
        for t in ["","0.0.0.0/0","1.0.1.1/24","1.0.1.0/33","2000::/3","not-an-ip/24"] { XCTAssertThrowsError(try PacketGate(cnCIDRs:t)) }
    }
}
