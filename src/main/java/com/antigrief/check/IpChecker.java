package com.antigrief.check;

import io.javalin.http.Context;

// вытаскивает реальный ip из запросов, учитывает прокси-заголовки
public class IpChecker {

    public String getIpFromWeb(Context ctx) {
        // x-forwarded-for может быть цепочкой: client, proxy1, proxy2
        String xff = ctx.header("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            String ip = xff.split(",")[0].trim();
            if (isValidIp(ip)) return normalizeIp(ip);
        }

        String realIp = ctx.header("X-Real-IP");
        if (realIp != null && !realIp.isEmpty() && isValidIp(realIp)) {
            return normalizeIp(realIp);
        }

        String cfIp = ctx.header("CF-Connecting-IP");
        if (cfIp != null && !cfIp.isEmpty() && isValidIp(cfIp)) {
            return normalizeIp(cfIp);
        }

        // фоллбэк — ip из сокета
        String remoteAddr = ctx.req().getRemoteAddr();
        if (remoteAddr != null && !remoteAddr.isEmpty()) {
            return normalizeIp(remoteAddr);
        }

        return "127.0.0.1";
    }

    // в mc адрес вида /192.168.1.1:12345
    public String extractIp(String address) {
        if (address == null) return "0.0.0.0";
        String clean = address.replace("/", "");
        int colonIdx = clean.lastIndexOf(':');
        if (colonIdx > 0) {
            return clean.substring(0, colonIdx);
        }
        return clean;
    }

    // [0:0:0:0:0:0:0:1] → 127.0.0.1
    private String normalizeIp(String ip) {
        if (ip == null) return "127.0.0.1";
        ip = ip.replace("[", "").replace("]", "");
        if (ip.equals("0:0:0:0:0:0:0:1") || ip.equals("::1")) {
            return "127.0.0.1";
        }
        return ip;
    }

    private boolean isValidIp(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        String[] parts = ip.split("\\.");
        if (parts.length == 4) {
            try {
                for (String part : parts) {
                    int num = Integer.parseInt(part);
                    if (num < 0 || num > 255) return false;
                }
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return ip.contains(":");
    }
}
