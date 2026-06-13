package com.antigrief.listener;

import com.antigrief.AntiGriefPlugin;
import com.antigrief.util.MessageUtil;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerMoveEvent;

// замороженные не могут двигаться
public class MoveListener implements Listener {

    private final AntiGriefPlugin plugin;

    public MoveListener(AntiGriefPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onMove(PlayerMoveEvent event) {
        String nick = event.getPlayer().getName();
        if (plugin.getFrozenPlayers().contains(nick)) {
            if (event.getFrom().getX() != event.getTo().getX() ||
                event.getFrom().getY() != event.getTo().getY() ||
                event.getFrom().getZ() != event.getTo().getZ()) {

                event.setCancelled(true);

                // напоминаем раз в 5 сек, не каждый тик
                long now = System.currentTimeMillis();
                Long last = reminderTimes.get(nick);
                if (last == null || now - last > 5000) {
                    String url = plugin.getConfigManager().getExternalUrl() + "/login?nick=" + nick;
                    event.getPlayer().sendMessage(MessageUtil.freezeMessage(url));
                    reminderTimes.put(nick, now);
                }
            }
        }
    }

    private final java.util.concurrent.ConcurrentHashMap<String, Long> reminderTimes = new java.util.concurrent.ConcurrentHashMap<>();
}
