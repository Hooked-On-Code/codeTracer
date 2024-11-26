// Highlights code in the listing view based on addresses from an ndjson file.
// @author King Slime
// @category CodeTracing
// @toolbar icons/ListingView.png
// @keybinding ctrl shift L

import java.awt.Color;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

public class HighlightListing extends GhidraScript {

    private Map<Address, List<Color>> addressColorMap = new HashMap<>();
    private AddressSet addressSet = new AddressSet();

    // Define color mapping for packetIndex values
    private static final Map<Integer, Color> PACKET_COLORS = Map.of(
        1, new Color(0, 204, 0, 255),       // Vibrant Green
        2, new Color(255, 204, 0, 255),     // Bright Yellow
        3, new Color(255, 102, 0, 255),     // Vibrant Orange
        4, new Color(204, 102, 0, 255),     // Deep Orange
        5, new Color(255, 255, 102, 255)    // Soft Yellow
    );


    @Override
    public void run() throws Exception {
        ColorizingService colorService = state.getTool().getService(ColorizingService.class);
        if (colorService == null) {
            printerr("Can't find ColorizingService.");
            return;
        }

        // Clear existing background colors
        colorService.clearAllBackgroundColors();
        println("Cleared all colors from the listing view.");

        // Load addresses and colors from the ndjson file
        loadAddressesFromNdjson();

        // Apply highlighting
        highlightAddresses(colorService);
    }

    private void loadAddressesFromNdjson() throws Exception {
        String filepath = askFile("Select the ndjson file", "Open").getAbsolutePath();

        try (BufferedReader reader = new BufferedReader(new FileReader(filepath))) {
            String line;
            JsonParser parser = new JsonParser();

            // Read the first line, which should be the modules.json content
            String modulesLine = reader.readLine();
            if (modulesLine == null) {
                println("File is empty.");
                return;
            }

            // Parse the modules.json content
            JsonArray modulesArray = parser.parse(modulesLine).getAsJsonArray();

            // Find the module that matches the program name
            String programModuleName = currentProgram.getName();
            JsonObject matchingModule = null;
            for (var moduleElement : modulesArray) {
                JsonObject moduleObject = moduleElement.getAsJsonObject();
                String moduleName = moduleObject.get("name").getAsString();
                if (moduleName.equals(programModuleName)) {
                    matchingModule = moduleObject;
                    break;
                }
            }

            if (matchingModule == null) {
                println("No matching module found for the current program.");
                return;
            }

            // Get the base address of the module in the trace data
            String traceBaseAddressStr = matchingModule.get("base").getAsString();
            Address traceBaseAddress = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(traceBaseAddressStr);

            // Get the base address of the current program in Ghidra
            Address ghidraBaseAddress = currentProgram.getImageBase();

            // Calculate the offset
            long addressOffset = ghidraBaseAddress.getOffset() - traceBaseAddress.getOffset();
            println("Ghidra base: 0x" + ghidraBaseAddress.toString());
            println("Trace base: 0x" + traceBaseAddress.toString());
            println("Calculated offset: 0x" + Long.toHexString(addressOffset));

            // Now read the rest of the ndjson file and process the trace data
            while ((line = reader.readLine()) != null) {
                JsonObject jsonObject = parser.parse(line).getAsJsonObject();

                // Handle prefix traces
                if (jsonObject.has("pI")) {
                    int packetIndex = jsonObject.get("pI").getAsInt();
                    Color color = PACKET_COLORS.get(packetIndex);

                    if (color == null) continue;

                    JsonArray detailsArray = jsonObject.getAsJsonArray("d");
                    for (var detailElement : detailsArray) {
                        String addressStr = detailElement.getAsString();
                        Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addressStr);

                        if (address != null) {
                            try {
                                Address adjustedAddress = address.add(addressOffset);
                                addressColorMap.computeIfAbsent(adjustedAddress, k -> new ArrayList<>()).add(color);
                            } catch (Exception e) {
                                // println("Address overflow: " + addressStr);
                            }
                        } else {
                            println("Unable to resolve address: " + addressStr);
                        }
                    }
                }
                // Handle range-based function traces like 'compile'
                else if (jsonObject.has("eT")) {
                    Color color = PACKET_COLORS.get(1); // just use the first 
                    JsonArray detailsArray = jsonObject.getAsJsonArray("d");

                    if (detailsArray.size() == 2) {
                        String startAddressStr = detailsArray.get(0).getAsString();
                        String endAddressStr = detailsArray.get(1).getAsString();

                        Address startAddress = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(startAddressStr);
                        Address endAddress = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(endAddressStr);

                        if (startAddress != null && endAddress != null) {
                            try {
                                Address adjustedStart = startAddress.add(addressOffset);
                                Address adjustedEnd = endAddress.add(addressOffset);

                                // Add range of addresses to address set
                                addressSet.addRange(adjustedStart, adjustedEnd);

                                for (Address addr = adjustedStart; addr.compareTo(adjustedEnd) <= 0; addr = addr.next()) {
                                    addressColorMap.computeIfAbsent(addr, k -> new ArrayList<>()).add(color);
                                }

                            } catch (Exception e) {
                                // println("Address overflow in range: " + startAddressStr + " to " + endAddressStr);
                            }
                        } else {
                            println("Unable to resolve range: " + startAddressStr + " to " + endAddressStr);
                        }
                    }
                }
            }
        }
    }

    private void highlightAddresses(ColorizingService colorService) {
        for (var entry : addressColorMap.entrySet()) {
            Address address = entry.getKey();
            List<Color> colors = entry.getValue();

            // Blend colors if multiple colors are associated with the address
            Color blendedColor = blendColors(colors);
            colorService.setBackgroundColor(address, address, blendedColor);
        }

        println("Total addresses highlighted: " + addressColorMap.size());
    }

    private Color blendColors(List<Color> colors) {
        int totalRed = 0, totalGreen = 0, totalBlue = 0;

        for (Color color : colors) {
            totalRed += color.getRed();
            totalGreen += color.getGreen();
            totalBlue += color.getBlue();
        }

        int count = colors.size();
        return new Color(totalRed / count, totalGreen / count, totalBlue / count, 150); // Semi-transparent
    }
}
