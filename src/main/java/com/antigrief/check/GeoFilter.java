package com.antigrief.check;

import com.antigrief.config.ConfigManager;
import java.util.List;

// проверяет страну по белому списку (снг)
public class GeoFilter {

    private final ConfigManager configManager;

    public GeoFilter(ConfigManager configManager) {
        this.configManager = configManager;
    }

    public boolean isCountryAllowed(String countryCode) {
        if (countryCode == null || countryCode.isEmpty()) return false;
        List<String> allowed = configManager.getAllowedCountries();
        return allowed.stream().anyMatch(c -> c.equalsIgnoreCase(countryCode));
    }

    public boolean isCountryAllowed(VpnChecker.VpnResult result) {
        if (result == null) return false;
        return isCountryAllowed(result.country);
    }

    public String getAllowedCountriesString() {
        return String.join(", ", configManager.getAllowedCountries());
    }
}
