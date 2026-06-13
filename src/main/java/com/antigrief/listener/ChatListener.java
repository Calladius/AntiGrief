package com.antigrief.listener;

import com.antigrief.AntiGriefPlugin;
import com.antigrief.util.MessageUtil;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerChatEvent;

// замороженные не могут писать в чат
public class ChatListener implements Listener {

    private final AntiGriefPlugin plugin;

    public ChatListener(AntiGriefPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onChat(AsyncPlayerChatEvent event) {
        String nick = event.getPlayer().getName();
        if (plugin.getFrozenPlayers().contains(nick)) {
            event.setCancelled(true);
            String url = plugin.getConfigManager().getExternalUrl() + "/login?nick=" + nick;
            event.getPlayer().sendMessage(MessageUtil.freezeMessage(url));
        }
    }
}
