import AppKit
import NetworkExtension
import SystemExtensions
import GuardCore

private let extensionID = "io.wujian.guard.packet"

@main final class GuardHost: NSObject, NSApplicationDelegate, OSSystemExtensionRequestDelegate {
    private var window: NSWindow!
    private let status = NSTextField(wrappingLabelWithString: "尚未启用。此开发组件仅实现手动隔断：启用后阻止非 CN 公网 IP 及公网 IPv6；不判断出口稳定性或自动恢复。")
    static func main() {
        let delegate = GuardHost()
        let app = NSApplication.shared
        app.delegate = delegate
        if CommandLine.arguments.contains("--status") { app.setActivationPolicy(.prohibited) }
        else { app.setActivationPolicy(.regular) }
        withExtendedLifetime(delegate) { app.run() }
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        if CommandLine.arguments.contains("--status") { queryStatus(json: true); return }
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 560, height: 240), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "无间道 · 系统隔断开发组件"
        let title = NSTextField(labelWithString: "系统隔断技术验证")
        title.font = .systemFont(ofSize: 20, weight: .semibold)
        let warning = NSTextField(wrappingLabelWithString: "此组件会影响整机网络，包括国外代理节点及相关连接。只在隔离测试机启用。解除操作在本机执行，不依赖网络。")
        warning.textColor = .secondaryLabelColor
        let buttons = NSStackView(views: [button("启用隔断", #selector(enable)), button("解除隔断", #selector(disable)), button("查询配置状态", #selector(refresh))])
        buttons.orientation = .horizontal; buttons.spacing = 10
        let stack = NSStackView(views: [title, warning, status, buttons]); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        window.contentView!.addSubview(stack)
        NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 24), stack.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -24), stack.topAnchor.constraint(equalTo: window.contentView!.topAnchor, constant: 24)])
        window.center(); window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
    private func button(_ title: String, _ action: Selector) -> NSButton { NSButton(title: title, target: self, action: action) }
    @objc private func enable() {
        guard Bundle.main.object(forInfoDictionaryKey: "WujianInstallable") as? Bool == true else {
            status.stringValue = "当前是编译验证包，未提供有效系统扩展签名与描述文件，禁止请求安装。"; return
        }
        do {
            guard let url = Bundle.main.url(forResource: "country-cn", withExtension: "txt") else { throw GuardDataError.invalidDatabase }
            _ = try PacketGate(cnCIDRs: String(contentsOf: url, encoding: .utf8))
        } catch { status.stringValue = "GeoIP 网段表无法验证，未申请安装或启用。"; return }
        status.stringValue = "正在申请系统扩展；等待 macOS 授权。"
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionID, queue: .main)
        request.delegate = self; OSSystemExtensionManager.shared.submitRequest(request)
    }
    @objc private func disable() { configure(enabled: false) }
    @objc private func refresh() { queryStatus(json: false) }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) { status.stringValue = "请在 macOS 系统设置中审核系统扩展授权；授权尚未完成，不显示阻断成功。" }
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if result == .completed { configure(enabled: true) }
        else { status.stringValue = "系统扩展请求需重启完成；尚未启用过滤。" }
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { status.stringValue = "系统扩展未启用：\(error.localizedDescription)" }
    private func configure(enabled: Bool) {
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { error in
            DispatchQueue.main.async {
                if let error { self.status.stringValue = error.localizedDescription; return }
                if let current = manager.providerConfiguration, current.filterPacketProviderBundleIdentifier != extensionID {
                    self.status.stringValue = "检测到非本组件的过滤配置，拒绝覆盖。"; return
                }
                if enabled {
                    let configuration = NEFilterProviderConfiguration()
                    configuration.filterPackets = true; configuration.filterSockets = false
                    configuration.filterPacketProviderBundleIdentifier = extensionID
                    configuration.vendorConfiguration = ["mode": "restricted"]
                    manager.providerConfiguration = configuration
                    manager.localizedDescription = "无间道国外 IP 隔断（开发验证）"
                } else if manager.providerConfiguration == nil { self.status.stringValue = "没有本组件的过滤配置。"; return }
                manager.isEnabled = enabled
                manager.saveToPreferences { error in DispatchQueue.main.async {
                    self.status.stringValue = error.map { "配置操作未完成：\($0.localizedDescription)" } ?? (enabled ? "过滤配置已提交开启；这不是实际断流验收证明。" : "过滤配置已提交关闭，请复测网络恢复情况。")
                } }
            }
        }
    }
    private func queryStatus(json: Bool) {
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { error in DispatchQueue.main.async {
            let ours = manager.providerConfiguration?.filterPacketProviderBundleIdentifier == extensionID
            let result: [String: Any] = ["configurationEnabled": ours && manager.isEnabled, "ownsConfiguration": ours, "enforcementVerified": false, "error": error?.localizedDescription ?? ""]
            if json {
                if let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]), let text = String(data: data, encoding: .utf8) { print(text) }
                NSApp.terminate(nil)
            } else { self.status.stringValue = error?.localizedDescription ?? "本组件配置开启：\(ours && manager.isEnabled ? "是" : "否")。实际阻断行为须单独验收。" }
        } }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
