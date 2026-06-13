package com.antigrief.listener;

import com.antigrief.AntiGriefPlugin;
import com.antigrief.util.MessageUtil;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityTargetEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerPickupItemEvent;
import org.bukkit.entity.Player;

// блокирует все действия замороженных
public class FreezeListener implements Listener {

    private final AntiGriefPlugin plugin;

    public FreezeListener(AntiGriefPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onBlockBreak(BlockBreakEvent event) {
        if (plugin.getFrozenPlayers().contains(event.getPlayer().getName())) {
            event.setCancelled(true);
            sendReminder(event.getPlayer());
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onBlockPlace(BlockPlaceEvent event) {
        if (plugin.getFrozenPlayers().contains(event.getPlayer().getName())) {
            event.setCancelled(true);
            sendReminder(event.getPlayer());
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInteract(PlayerInteractEvent event) {
        if (plugin.getFrozenPlayers().contains(event.getPlayer().getName())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInventoryClick(InventoryClickEvent event) {
        if (event.getWhoClicked() instanceof Player player) {
            if (plugin.getFrozenPlayers().contains(player.getName())) {
                event.setCancelled(true);
                sendReminder(player);
            }
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInventoryOpen(InventoryOpenEvent event) {
        if (event.getPlayer() instanceof Player player) {
            if (plugin.getFrozenPlayers().contains(player.getName())) {
                event.setCancelled(true);
            }
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onItemDrop(PlayerDropItemEvent event) {
        if (plugin.getFrozenPlayers().contains(event.getPlayer().getName())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onItemPickup(PlayerPickupItemEvent event) {
        if (plugin.getFrozenPlayers().contains(event.getPlayer().getName())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onEntityDamageByEntity(EntityDamageByEntityEvent event) {
        if (event.getDamager() instanceof Player player) {
            if (plugin.getFrozenPlayers().contains(player.getName())) {
                event.setCancelled(true);
            }
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onEntityTarget(EntityTargetEvent event) {
        if (event.getTarget() instanceof Player player) {
            if (plugin.getFrozenPlayers().contains(player.getName())) {
                event.setCancelled(true);
            }
        }
    }

    // напоминаем раз в 5 сек чтобы не спамить
    private final java.util.concurrent.ConcurrentHashMap<String, Long> reminderTimes = new java.util.concurrent.ConcurrentHashMap<>();

    private void sendReminder(Player player) {
        long now = System.currentTimeMillis();
        Long last = reminderTimes.get(player.getName());
        if (last == null || now - last > 5000) {
            String url = plugin.getConfigManager().getExternalUrl() + "/login?nick=" + player.getName();
            player.sendMessage(MessageUtil.freezeMessage(url));
            reminderTimes.put(player.getName(), now);
        }
    }
}
