package com.antigrief.util;

import com.antigrief.config.ConfigManager;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

public class MessageUtil {

    private static ConfigManager configManager;

    public static void init(ConfigManager cm) {
        configManager = cm;
    }

    public static String format(String message) {
        if (message == null) return "";
        return message.replace("&", "\u00a7");
    }

    public static String prefixed(String message) {
        String prefix = configManager != null ? configManager.getPrefix() : "\u00a78[\u00a76AntiGrief\u00a78] \u00a7f";
        return format(prefix + message);
    }

    public static Component component(String message) {
        return LegacyComponentSerializer.legacyAmpersand().deserialize(message);
    }

    // кликабельная ссылка для замороженных
    public static Component freezeMessage(String url) {
        return freezeMessageWithText(url, "\u0412\u044b \u0437\u0430\u043c\u043e\u0440\u043e\u0436\u0435\u043d\u044b! ");
    }

    public static Component freezeMessageWithText(String url, String message) {
        var prefix = Component.text("[AntiGrief] ")
            .color(net.kyori.adventure.text.format.NamedTextColor.DARK_GRAY);
        var freezeText = Component.text(message)
            .color(net.kyori.adventure.text.format.NamedTextColor.YELLOW);
        var linkText = Component.text("\u041d\u0430\u0436\u043c\u0438\u0442\u0435 \u0441\u044e\u0434\u0430 \u0434\u043b\u044f \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u044f")
            .color(net.kyori.adventure.text.format.NamedTextColor.GREEN)
            .decorate(net.kyori.adventure.text.format.TextDecoration.UNDERLINED)
            .clickEvent(net.kyori.adventure.text.event.ClickEvent.openUrl(url))
            .hoverEvent(net.kyori.adventure.text.event.HoverEvent.showText(
                Component.text("\u041e\u0442\u043a\u0440\u043e\u0435\u0442 \u0441\u0430\u0439\u0442 \u0432\u0445\u043e\u0434\u0430 \u0432 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0435")
                    .color(net.kyori.adventure.text.format.NamedTextColor.GRAY)
            ));

        return prefix.append(freezeText).append(linkText);
    }

    // ссылка на сайт для незамороженных
    public static Component siteLinkMessage(String url) {
        var prefix = Component.text("[AntiGrief] ")
            .color(net.kyori.adventure.text.format.NamedTextColor.DARK_GRAY);
        var linkText = Component.text("\u041f\u0435\u0440\u0435\u0439\u0434\u0438\u0442\u0435 \u043d\u0430 \u0441\u0430\u0439\u0442 \u0434\u043b\u044f \u0443\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u0438\u044f \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u043e\u043c")
            .color(net.kyori.adventure.text.format.NamedTextColor.GREEN)
            .decorate(net.kyori.adventure.text.format.TextDecoration.UNDERLINED)
            .clickEvent(net.kyori.adventure.text.event.ClickEvent.openUrl(url))
            .hoverEvent(net.kyori.adventure.text.event.HoverEvent.showText(
                Component.text("\u041e\u0442\u043a\u0440\u043e\u0435\u0442 \u0441\u0430\u0439\u0442 \u0432 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0435")
                    .color(net.kyori.adventure.text.format.NamedTextColor.GRAY)
            ));

        return prefix.append(linkText);
    }
}
