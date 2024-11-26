// Highlights the coresponding lines in the decompiled view from the listing view

// @author: King Slime
// @category: CodeTracing
// @toolbar: icons/DecompiledView.png
// @keybinding: ctrl shift K

import java.awt.Color;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.CTokenHighlightMatcher;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompilerHighlighter;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.decompiler.DecompilerHighlightService;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.framework.plugintool.PluginTool;

public class HighlightDecompiled extends GhidraScript {

    @Override
    public void run() throws Exception {
        
        // Get the function containing the current address
        Function currentFunction = getFunctionContaining(currentAddress);
        if (currentFunction == null) {
            println("No function found at the current address.");
            return;
        }

        println("Function Name: " + currentFunction.getName());
        println("Function Address Range: " + currentFunction.getBody());

        // Get the Listing object, which provides access to the instructions
        Listing listing = currentProgram.getListing();

        // Create a map to hold addresses and their colors
        Map<Address, Color> highlightedAddresses = new HashMap<>();

        // Iterate over each instruction in the function's body
        for (Instruction instruction : listing.getInstructions(currentFunction.getBody(), true)) {
            Color color = checkHighlight(instruction);
            if (color != null) {
                highlightedAddresses.put(instruction.getMinAddress(), color);
            }
        }

        println("Finished iterating over instructions.");

        // Highlight the decompiled view with the collected addresses and colors
        highlightDecompiledFunction(currentFunction, highlightedAddresses);
    }

    public Color checkHighlight(Instruction instruction) {
        // Get the ColorizingService from the current tool
        ColorizingService colorizingService = state.getTool().getService(ColorizingService.class);
        if (colorizingService == null) {
            println("ColorizingService not found.");
            return null;
        }

        // Get the address of the instruction
        Address instructionAddress = instruction.getMinAddress();

        return colorizingService.getBackgroundColor(instructionAddress);
    }

    private void highlightDecompiledFunction(Function function, Map<Address, Color> highlightedAddresses) {
        PluginTool tool = state.getTool();
        DecompilerHighlightService service = tool.getService(DecompilerHighlightService.class);
        if (service == null) {
            println("DecompilerHighlightService not found.");
            return;
        }
    
        // Decompile the function
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        DecompileResults decompileResults = decompiler.decompileFunction(function, 30, monitor);
    
        if (!decompileResults.decompileCompleted()) {
            println("Decompilation failed for function: " + function.getName());
            return;
        }
    
        // Create and apply a single highlighter for all specified addresses and colors
        CTokenHighlightMatcher matcher = new MyMatcher(highlightedAddresses);
        DecompilerHighlighter highlighter = service.createHighlighter(getClass().getName(), matcher);
        highlighter.applyHighlights();
    
        // println("Applied highlights for addresses: " + highlightedAddresses.keySet());
    }

    // Custom matcher class to highlight specific addresses with specific colors
    class MyMatcher implements CTokenHighlightMatcher {
        private Map<Address, Color> addressColorMap; // Map of addresses and their colors
    
        public MyMatcher(Map<Address, Color> addressColorMap) {
            this.addressColorMap = addressColorMap;
        }
    
        @Override
        public Color getTokenHighlight(ClangToken token) {
            Address tokenAddress = token.getMinAddress();
            if (tokenAddress != null && addressColorMap.containsKey(tokenAddress)) {
                return addressColorMap.get(tokenAddress);  // Use the specific color for each address
            }
            return null;  // No highlight for non-matching tokens
        }
    }
}
