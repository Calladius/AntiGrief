package com.antigrief.listener;

import com.antigrief.AntiGriefPlugin;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerQuitEvent;

// убирает игрока из заморозки при выходе
public class QuitListener implements Listener {

    private final AntiGriefPlugin plugin;

    public QuitListener(AntiGriefPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onQuit(PlayerQuitEvent event) {
        plugin.getFrozenPlayers().remove(event.getPlayer().getName());
    }
}
