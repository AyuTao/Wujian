import { useEffect, useRef } from "react";
import * as THREE from "three";

export type RoleType = "jianming" | "yongren";

export interface PersonaHUDData {
  isArmed: boolean;
  localDns: string;
  webrtcStatus: string;
  egressIp: string;
  isIpPinned: boolean;
  pinnedIpValue?: string | null;
  region: string;
  currentTimezone: string;
  isTimezoneSynced: boolean;
}

interface ThreePersonaProps {
  activeRole: RoleType;
  onSelectRole: (role: RoleType) => void;
  hudData: PersonaHUDData;
}

/**
 * 纯代码程序化手绘《无间道》双雄对峙电影海报
 * 检测数据直接烙印在海报左右双雄人物身侧，随 3D 空间一同旋转倾斜
 */
function drawPosterToCanvas(
  canvas: HTMLCanvasElement,
  hudData: PersonaHUDData,
  activeRole: RoleType,
) {
  const ctx = canvas.getContext("2d")!;
  const w = canvas.width;
  const h = canvas.height;

  ctx.clearRect(0, 0, w, h);

  // 1. 电影深黑底色与微光渐变
  const bgGrad = ctx.createLinearGradient(0, 0, 0, h);
  bgGrad.addColorStop(0, "#040608");
  bgGrad.addColorStop(0.35, "#0a0e16");
  bgGrad.addColorStop(0.75, "#070a10");
  bgGrad.addColorStop(1, "#020305");
  ctx.fillStyle = bgGrad;
  ctx.fillRect(0, 0, w, h);

  // 2. 远景：雨夜大厦与天际线阴影
  ctx.fillStyle = "rgba(15, 23, 42, 0.4)";
  for (let i = 0; i < 9; i++) {
    const bw = 80 + (i % 3) * 35;
    const bh = 320 + ((i * 47) % 220);
    const bx = 40 + i * 110;
    const by = 800 - bh;
    ctx.fillRect(bx, by, bw, bh + 400);

    // 建筑微弱窗格光点
    ctx.fillStyle = "rgba(148, 163, 184, 0.08)";
    for (let r = 0; r < bh - 40; r += 26) {
      for (let c = 10; c < bw - 15; c += 22) {
        if ((r * 13 + c * 7) % 5 === 0) {
          ctx.fillRect(bx + c, by + r, 8, 12);
        }
      }
    }
    ctx.fillStyle = "rgba(15, 23, 42, 0.4)";
  }

  // 3. 纵向中轴撕裂分界线（冷青 vs 暖金对撞）
  const splitGrad = ctx.createLinearGradient(480, 0, 544, 0);
  splitGrad.addColorStop(0, "rgba(56, 189, 248, 0.25)");
  splitGrad.addColorStop(0.5, "rgba(255, 255, 255, 0.5)");
  splitGrad.addColorStop(1, "rgba(245, 158, 11, 0.25)");
  ctx.fillStyle = splitGrad;
  ctx.fillRect(508, 0, 8, h);

  // 4. 左雄：刘建明（Anthropic 驻机审查官）
  ctx.save();
  ctx.beginPath();
  ctx.moveTo(120, 680);
  ctx.lineTo(210, 570);
  ctx.lineTo(240, 480);
  ctx.lineTo(315, 455);
  ctx.lineTo(300, 425);
  ctx.lineTo(320, 405);
  ctx.lineTo(285, 380);
  ctx.lineTo(345, 330);
  ctx.lineTo(290, 270);
  ctx.lineTo(305, 210);
  ctx.lineTo(240, 150);
  ctx.lineTo(150, 170);
  ctx.lineTo(90, 260);
  ctx.lineTo(120, 440);
  ctx.lineTo(60, 680);
  ctx.closePath();

  const jmGrad = ctx.createRadialGradient(280, 340, 40, 240, 340, 220);
  jmGrad.addColorStop(0, "#2a394a");
  jmGrad.addColorStop(0.6, "#151e29");
  jmGrad.addColorStop(1, "#090d13");
  ctx.fillStyle = jmGrad;
  ctx.fill();

  // 侧光轮廓
  ctx.lineWidth = 4;
  ctx.strokeStyle =
    activeRole === "jianming"
      ? "rgba(56, 189, 248, 0.95)"
      : "rgba(56, 189, 248, 0.65)";
  ctx.shadowColor = "#38bdf8";
  ctx.shadowBlur = activeRole === "jianming" ? 22 : 12;
  ctx.beginPath();
  ctx.moveTo(305, 210);
  ctx.lineTo(290, 270);
  ctx.lineTo(345, 330);
  ctx.lineTo(285, 380);
  ctx.lineTo(320, 405);
  ctx.lineTo(300, 425);
  ctx.lineTo(315, 455);
  ctx.lineTo(240, 480);
  ctx.stroke();

  // 眼睛神采
  ctx.fillStyle = "#e0f2fe";
  ctx.shadowBlur = 8;
  ctx.beginPath();
  ctx.arc(282, 292, 3.5, 0, Math.PI * 2);
  ctx.fill();
  ctx.restore();

  // 刘建明西装领口
  ctx.save();
  ctx.beginPath();
  ctx.moveTo(70, 680);
  ctx.lineTo(200, 640);
  ctx.lineTo(270, 680);
  ctx.lineTo(250, 1020);
  ctx.lineTo(0, 1020);
  ctx.lineTo(0, 710);
  ctx.closePath();
  ctx.fillStyle = "#0c131d";
  ctx.fill();

  ctx.strokeStyle = "rgba(226, 232, 240, 0.65)";
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  ctx.moveTo(215, 640);
  ctx.lineTo(235, 730);
  ctx.lineTo(255, 645);
  ctx.stroke();

  // 刘建明雷达准星
  ctx.strokeStyle = "rgba(56, 189, 248, 0.35)";
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.arc(280, 300, 65, 0, Math.PI * 2);
  ctx.moveTo(195, 300);
  ctx.lineTo(365, 300);
  ctx.moveTo(280, 215);
  ctx.lineTo(280, 385);
  ctx.stroke();

  // 左侧海报内嵌 HUD 数据 (直接融入海报，代替独立卡片)
  ctx.font = "bold 20px ui-monospace, SFMono-Regular, monospace";
  ctx.fillStyle = "#38bdf8";
  ctx.fillText("PROBE // ANTHROPIC INQUISITOR", 50, 750);
  ctx.font = "15px sans-serif";
  ctx.fillStyle = "rgba(226, 232, 240, 0.85)";
  ctx.fillText("刘建明 · 本机审查暗桩", 50, 780);

  // 4 项检测数据指标 (直接刻在海报上)
  const drawLeftMetric = (
    y: number,
    num: string,
    label: string,
    val: string,
    isOk: boolean,
  ) => {
    ctx.font = "bold 12px ui-monospace, monospace";
    ctx.fillStyle = "rgba(56, 189, 248, 0.6)";
    ctx.fillText(num, 50, y);
    ctx.font = "13px 'PingFang SC', sans-serif";
    ctx.fillStyle = "rgba(203, 213, 225, 0.75)";
    ctx.fillText(label, 75, y);

    ctx.font = "bold 13px ui-monospace, monospace";
    ctx.fillStyle = isOk ? "#38bdf8" : "#f87171";
    ctx.fillText(val, 230, y);

    // 细分割线
    ctx.strokeStyle = "rgba(56, 189, 248, 0.15)";
    ctx.beginPath();
    ctx.moveTo(50, y + 8);
    ctx.lineTo(440, y + 8);
    ctx.stroke();
  };

  drawLeftMetric(
    825,
    "[01]",
    "物理网卡直连出站",
    hudData.isArmed ? "0% (已物理闭锁)" : "EXPOSED (直连泄露)",
    hudData.isArmed,
  );
  drawLeftMetric(
    865,
    "[02]",
    "53端口明文 DNS",
    hudData.isArmed ? "FAIL-CLOSED (静默)" : hudData.localDns || "192.168.1.1",
    hudData.isArmed,
  );
  drawLeftMetric(
    870 + 40,
    "[03]",
    "WebRTC STUN 穿透",
    hudData.webrtcStatus === "match" ? "BLOCKED (安全拦截)" : "LEAKED (有泄露)",
    hudData.webrtcStatus === "match",
  );
  drawLeftMetric(
    870 + 80,
    "[04]",
    "驻机暗桩审查判定",
    hudData.isArmed ? "CLEARED (抓不到马脚)" : "FAIL (真实底细已暴露)",
    hudData.isArmed,
  );
  ctx.restore();

  // 5. 右雄：陈永仁（潜入 Anthropic 卧底）
  ctx.save();
  ctx.beginPath();
  ctx.moveTo(904, 680);
  ctx.lineTo(814, 570);
  ctx.lineTo(784, 485);
  ctx.lineTo(709, 460);
  ctx.lineTo(724, 430);
  ctx.lineTo(704, 410);
  ctx.lineTo(739, 385);
  ctx.lineTo(679, 335);
  ctx.lineTo(734, 275);
  ctx.lineTo(719, 215);
  ctx.lineTo(770, 155);
  ctx.lineTo(795, 190);
  ctx.lineTo(820, 145);
  ctx.lineTo(874, 170);
  ctx.lineTo(934, 260);
  ctx.lineTo(904, 440);
  ctx.lineTo(964, 680);
  ctx.closePath();

  const cyrGrad = ctx.createRadialGradient(744, 340, 40, 784, 340, 220);
  cyrGrad.addColorStop(0, "#3d2d20");
  cyrGrad.addColorStop(0.6, "#22170f");
  cyrGrad.addColorStop(1, "#0d0906");
  ctx.fillStyle = cyrGrad;
  ctx.fill();

  // 暖光轮廓
  ctx.lineWidth = 4;
  ctx.strokeStyle =
    activeRole === "yongren"
      ? "rgba(245, 158, 11, 0.95)"
      : "rgba(245, 158, 11, 0.65)";
  ctx.shadowColor = "#f59e0b";
  ctx.shadowBlur = activeRole === "yongren" ? 22 : 12;
  ctx.beginPath();
  ctx.moveTo(719, 215);
  ctx.lineTo(734, 275);
  ctx.lineTo(679, 335);
  ctx.lineTo(739, 385);
  ctx.lineTo(704, 410);
  ctx.lineTo(724, 430);
  ctx.lineTo(709, 460);
  ctx.lineTo(784, 485);
  ctx.stroke();

  // 眼睛神采
  ctx.fillStyle = "#fef3c7";
  ctx.shadowBlur = 8;
  ctx.beginPath();
  ctx.arc(742, 295, 3.5, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = "rgba(245, 158, 11, 0.25)";
  for (let s = 0; s < 18; s++) {
    const rx = 720 + Math.random() * 50;
    const ry = 445 + Math.random() * 35;
    ctx.fillRect(rx, ry, 1.5, 1.5);
  }
  ctx.restore();

  // 陈永仁皮衣
  ctx.save();
  ctx.beginPath();
  ctx.moveTo(954, 680);
  ctx.lineTo(824, 640);
  ctx.lineTo(754, 685);
  ctx.lineTo(774, 1020);
  ctx.lineTo(1024, 1020);
  ctx.lineTo(1024, 710);
  ctx.closePath();
  ctx.fillStyle = "#16110d";
  ctx.fill();

  ctx.strokeStyle = "rgba(180, 83, 9, 0.65)";
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  ctx.moveTo(809, 640);
  ctx.lineTo(789, 740);
  ctx.lineTo(769, 650);
  ctx.stroke();

  // 陈永仁雷达准星
  ctx.strokeStyle = "rgba(245, 158, 11, 0.35)";
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.arc(744, 300, 65, 0, Math.PI * 2);
  ctx.moveTo(659, 300);
  ctx.lineTo(829, 300);
  ctx.moveTo(744, 215);
  ctx.lineTo(744, 385);
  ctx.stroke();

  // 右侧海报内嵌 HUD 数据 (直接融入海报，代替独立卡片)
  ctx.font = "bold 20px ui-monospace, SFMono-Regular, monospace";
  ctx.fillStyle = "#f59e0b";
  ctx.fillText("OPERATIVE // UNDERCOVER DEEP", 560, 750);
  ctx.font = "15px sans-serif";
  ctx.fillStyle = "rgba(226, 232, 240, 0.85)";
  ctx.fillText("陈永仁 · 潜入总部卧底", 560, 780);

  const drawRightMetric = (
    y: number,
    num: string,
    label: string,
    val: string,
    isOk: boolean,
  ) => {
    ctx.font = "bold 12px ui-monospace, monospace";
    ctx.fillStyle = "rgba(245, 158, 11, 0.6)";
    ctx.fillText(num, 560, y);
    ctx.font = "13px 'PingFang SC', sans-serif";
    ctx.fillStyle = "rgba(203, 213, 225, 0.75)";
    ctx.fillText(label, 585, y);

    ctx.font = "bold 13px ui-monospace, monospace";
    ctx.fillStyle = isOk ? "#10b981" : "#f59e0b";
    ctx.fillText(val, 740, y);

    ctx.strokeStyle = "rgba(245, 158, 11, 0.15)";
    ctx.beginPath();
    ctx.moveTo(560, y + 8);
    ctx.lineTo(950, y + 8);
    ctx.stroke();
  };

  const egressDisplay = hudData.isIpPinned
    ? `${hudData.egressIp || "已锁定"} [PINNED]`
    : hudData.egressIp || "等待排查";
  drawRightMetric(
    825,
    "[01]",
    "远端代理出口 IP",
    egressDisplay,
    Boolean(hudData.egressIp && hudData.egressIp !== "等待排查"),
  );
  drawRightMetric(
    865,
    "[02]",
    "系统假面时区",
    `${hudData.currentTimezone} ${hudData.isTimezoneSynced ? "[MATCHED]" : "[DESYNC]"}`,
    hudData.isTimezoneSynced,
  );
  drawRightMetric(
    870 + 40,
    "[03]",
    "Fail-Closed 断路保护",
    hudData.isArmed ? "ARMED (闭锁守护)" : "DISARMED (未武装)",
    hudData.isArmed,
  );
  drawRightMetric(
    870 + 80,
    "[04]",
    "总部卧底接应裁决",
    hudData.isArmed && hudData.isTimezoneSynced
      ? "INFILTRATED (完美潜伏)"
      : "RISK (存在破绽需武装)",
    hudData.isArmed && hudData.isTimezoneSynced,
  );
  ctx.restore();

  // 6. 底部书法大字标题与对峙口号
  ctx.save();
  ctx.textAlign = "center";
  ctx.font = "900 100px 'PingFang SC', 'Source Han Serif SC', serif";
  ctx.fillStyle = "rgba(248, 250, 252, 0.94)";
  ctx.shadowColor = "rgba(0, 0, 0, 0.95)";
  ctx.shadowBlur = 24;
  ctx.fillText("無 間 道", 512, 1120);

  ctx.font = "700 22px ui-monospace, monospace";
  ctx.fillStyle = "rgba(148, 163, 184, 0.75)";
  ctx.fillText("INFERNAL AFFAIRS : AI ACCESS PROTOCOL", 512, 1165);

  ctx.font = "500 15px 'PingFang SC', sans-serif";
  ctx.fillStyle = "rgba(255, 255, 255, 0.45)";
  ctx.fillText("三 年 之 后 又 三 年 · 对 不 起 我 是 审 查 官", 512, 1205);
  ctx.restore();

  // 7. 电影胶片颗粒噪点
  const imgData = ctx.getImageData(0, 0, w, h);
  const data = imgData.data;
  for (let i = 0; i < data.length; i += 4) {
    const noise = (Math.random() - 0.5) * 18;
    data[i] = Math.min(255, Math.max(0, data[i] + noise));
    data[i + 1] = Math.min(255, Math.max(0, data[i + 1] + noise));
    data[i + 2] = Math.min(255, Math.max(0, data[i + 2] + noise));
  }
  ctx.putImageData(imgData, 0, 0);
}

export function ThreePersona({
  activeRole,
  onSelectRole,
  hudData,
}: ThreePersonaProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const textureRef = useRef<THREE.CanvasTexture | null>(null);

  const activeRoleRef = useRef(activeRole);
  activeRoleRef.current = activeRole;

  // 当外部检测数据改变时，重绘海报纹理
  useEffect(() => {
    if (canvasRef.current && textureRef.current) {
      drawPosterToCanvas(canvasRef.current, hudData, activeRole);
      textureRef.current.needsUpdate = true;
    }
  }, [hudData, activeRole]);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    // 1. 初始化 Canvas 纹理
    const canvas = document.createElement("canvas");
    canvas.width = 1024;
    canvas.height = 1280;
    canvasRef.current = canvas;

    drawPosterToCanvas(canvas, hudData, activeRoleRef.current);

    const texture = new THREE.CanvasTexture(canvas);
    texture.generateMipmaps = true;
    textureRef.current = texture;

    // 2. 场景与相机
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 100);
    camera.position.set(0, 0, 3.6);

    // 3. 渲染器
    const renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: true,
      powerPreference: "high-performance",
    });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.35;
    container.appendChild(renderer.domElement);

    // 4. 海报 3D Mesh
    const boardWidth = 1.5;
    const boardHeight = 1.875;
    const boardGeo = new THREE.PlaneGeometry(boardWidth, boardHeight, 16, 16);

    const posterMat = new THREE.MeshStandardMaterial({
      map: texture,
      roughness: 0.35,
      metalness: 0.15,
      side: THREE.DoubleSide,
    });
    const posterMesh = new THREE.Mesh(boardGeo, posterMat);
    scene.add(posterMesh);

    // 悬浮外边框冷光细线 (武装时透出闭锁稳固绿光)
    const frameGeo = new THREE.EdgesGeometry(boardGeo);
    const frameMat = new THREE.LineBasicMaterial({
      color: hudData.isArmed ? 0x10b981 : 0x475569,
      transparent: true,
      opacity: hudData.isArmed ? 0.7 : 0.35,
    });
    const frame = new THREE.LineSegments(frameGeo, frameMat);
    posterMesh.add(frame);

    // 左右角色 3D 光晕
    const halfWidth = boardWidth * 0.46;
    const holoGeo = new THREE.PlaneGeometry(halfWidth, boardHeight * 0.94);
    const jianmingHoloMat = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.05,
      side: THREE.DoubleSide,
    });
    const jianmingHolo = new THREE.Mesh(holoGeo, jianmingHoloMat);
    jianmingHolo.position.set(-boardWidth * 0.24, 0, 0.02);
    posterMesh.add(jianmingHolo);

    const yongrenHoloMat = new THREE.MeshBasicMaterial({
      color: 0xf59e0b,
      transparent: true,
      opacity: 0.05,
      side: THREE.DoubleSide,
    });
    const yongrenHolo = new THREE.Mesh(holoGeo, yongrenHoloMat);
    yongrenHolo.position.set(boardWidth * 0.24, 0, 0.02);
    posterMesh.add(yongrenHolo);

    // 漂浮微粒
    const particleCount = 75;
    const particleGeo = new THREE.BufferGeometry();
    const posArray = new Float32Array(particleCount * 3);
    for (let i = 0; i < particleCount; i++) {
      posArray[i * 3] = (Math.random() - 0.5) * 4.4;
      posArray[i * 3 + 1] = (Math.random() - 0.5) * 4.0;
      posArray[i * 3 + 2] = (Math.random() - 0.5) * 1.6;
    }
    particleGeo.setAttribute(
      "position",
      new THREE.BufferAttribute(posArray, 3),
    );
    const particleMat = new THREE.PointsMaterial({
      size: 0.022,
      color: 0xcfdbe8,
      transparent: true,
      opacity: 0.6,
      blending: THREE.AdditiveBlending,
    });
    const particles = new THREE.Points(particleGeo, particleMat);
    scene.add(particles);

    // 灯光
    const ambLight = new THREE.AmbientLight(0xffffff, 1.05);
    scene.add(ambLight);

    const dirLightLeft = new THREE.DirectionalLight(0x38bdf8, 1.8);
    dirLightLeft.position.set(-2.5, 1.8, 3);
    scene.add(dirLightLeft);

    const dirLightRight = new THREE.DirectionalLight(0xf59e0b, 1.8);
    dirLightRight.position.set(2.5, 1.8, 3);
    scene.add(dirLightRight);

    // 自适应调整尺寸与相机视角 (Responsive Resize)
    const updateSize = () => {
      if (!container) return;
      const w = container.clientWidth;
      const h = container.clientHeight;
      if (w === 0 || h === 0) return;

      camera.aspect = w / h;
      // 保证海报纵向和横向都能完整优雅显示
      const targetAspect = boardWidth / boardHeight;
      if (camera.aspect < targetAspect) {
        // 窄屏：拉远相机以适应宽度
        camera.position.z = 3.6 * (targetAspect / camera.aspect);
      } else {
        // 宽屏：保持舒适高度
        camera.position.z = 3.6;
      }

      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };

    updateSize();

    // 视差与点击交互
    const targetTilt = { x: 0, y: 0 };
    const currentTilt = { x: 0, y: 0 };

    const onPointerMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      const x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      const y = -(((e.clientY - rect.top) / rect.height) * 2 - 1);
      targetTilt.x = y * 0.14;
      targetTilt.y = x * 0.2;
    };

    const onClick = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      const x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      if (x < 0) {
        onSelectRole("jianming");
      } else {
        onSelectRole("yongren");
      }
    };

    container.addEventListener("mousemove", onPointerMove);
    container.addEventListener("click", onClick);
    window.addEventListener("resize", updateSize);

    // 动画循环
    let animId: number;
    const startTime = performance.now();

    const animate = () => {
      animId = requestAnimationFrame(animate);
      const time = (performance.now() - startTime) * 0.001;

      currentTilt.x += (targetTilt.x - currentTilt.x) * 0.08;
      currentTilt.y += (targetTilt.y - currentTilt.y) * 0.08;

      posterMesh.rotation.x = currentTilt.x;
      posterMesh.rotation.y = currentTilt.y;
      posterMesh.position.y = Math.sin(time * 1.3) * 0.02;

      const isJianming = activeRoleRef.current === "jianming";
      const isYongren = activeRoleRef.current === "yongren";

      jianmingHoloMat.opacity = isJianming
        ? 0.16 + Math.sin(time * 3.5) * 0.04
        : 0.03;
      yongrenHoloMat.opacity = isYongren
        ? 0.16 + Math.sin(time * 3.5) * 0.04
        : 0.03;

      const positions = particleGeo.attributes.position.array as Float32Array;
      for (let i = 0; i < particleCount; i++) {
        positions[i * 3 + 1] += 0.0015;
        if (positions[i * 3 + 1] > 2.0) {
          positions[i * 3 + 1] = -2.0;
        }
      }
      particleGeo.attributes.position.needsUpdate = true;
      particles.rotation.y = time * 0.02;

      renderer.render(scene, camera);
    };
    animate();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", updateSize);
      container.removeEventListener("mousemove", onPointerMove);
      container.removeEventListener("click", onClick);
      renderer.dispose();
      texture.dispose();
      boardGeo.dispose();
      posterMat.dispose();
      frameGeo.dispose();
      frameMat.dispose();
      particleGeo.dispose();
      particleMat.dispose();
      holoGeo.dispose();
      jianmingHoloMat.dispose();
      yongrenHoloMat.dispose();
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
    };
  }, [onSelectRole]);

  return (
    <div
      ref={mountRef}
      style={{
        width: "100%",
        height: "100%",
        cursor: "pointer",
        position: "relative",
      }}
      title="点击海报左侧选择【刘建明·暗桩审查】，点击右侧选择【陈永仁·潜伏卧底】"
    />
  );
}
