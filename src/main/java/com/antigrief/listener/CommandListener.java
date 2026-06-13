package com.antigrief.listener;

import com.antigrief.AntiGriefPlugin;
import com.antigrief.util.MessageUtil;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;

// замороженным доступна только /angri
public class CommandListener implements Listener {

    private final AntiGriefPlugin plugin;

    public CommandListener(AntiGriefPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        String nick = event.getPlayer().getName();
        if (plugin.getFrozenPlayers().contains(nick)) {
            if (event.getMessage().toLowerCase().trim().startsWith("/angri")) {
                return;
            }
            event.setCancelled(true);
            String url = plugin.getConfigManager().getExternalUrl() + "/login?nick=" + nick;
            event.getPlayer().sendMessage(MessageUtil.freezeMessage(url));
        }
    }
}
