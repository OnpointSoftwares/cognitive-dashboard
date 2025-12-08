#ifndef FIREWALL_ENFORCE_H
#define FIREWALL_ENFORCE_H

#include <cstdint>
#include <string>
#include <atomic>
#include <map>

// ====================================================================
// A) Enforcement Decision Structure (Data-Plane Action)
//    This is the core result of packet analysis.
// ====================================================================

/**
 * @brief Defines the action to be taken on a packet or flow.
 */
enum class FirewallAction : uint8_t {
    PASS = 0,    // Allow the packet/flow to proceed
    DROP = 1,    // Discard the packet immediately (silent)
    REJECT = 2,  // Discard and send an ICMP/TCP RST notification
    RATE_LIMIT = 3 // Throttle the flow (Advanced)
};

/**
 * @brief Represents the decision made by the packet processing logic.
 */
struct PacketDecision {
    FirewallAction action;
    // Optional: a short string/ID indicating which policy triggered the action
    std::string rule_id; 
};


// ====================================================================
// B) Abstraction for the Enforcement Engine (Control-Plane Interface)
//    This would be the interface to update the fast-path rules.
// ====================================================================

// Define a simple Flow Identifier (e.g., source IP/port, dest IP/port, protocol)
// For a real system, this would be more complex (e.g., a union or struct of 5-tuple).
using FlowKey = uint64_t; // A simplified hash of the 5-tuple for lookup

/**
 * @brief Abstract class for the enforcement layer. 
 * This separates the decision logic from the capture/forwarding logic.
 */
class EnforcementEngine {
public:
    virtual ~EnforcementEngine() = default;

    /**
     * @brief Looks up or calculates the decision for a new packet/flow.
     * @param packet_data Pointer to the raw packet data.
     * @param len Length of the packet.
     * @return The determined action.
     */
    virtual PacketDecision get_decision(const uint8_t* packet_data, uint16_t len) = 0;
    
    /**
     * @brief Adds a specific flow to a policy table (e.g., ban this malicious flow).
     * @param flow_id The identifier for the flow to enforce a policy on.
     * @param action The action to take (e.g., DROP).
     */
    virtual void enforce_flow_policy(FlowKey flow_id, FirewallAction action) = 0;

    /**
     * @brief Gets the current default action if no rule matches.
     */
    virtual FirewallAction get_default_action() const = 0;
};


// ====================================================================
// C) Simple Implementation Example (In a separate .cpp file)
// ====================================================================

// A basic map to simulate flow tracking and banning.
class SimpleFlowEnforcer : public EnforcementEngine {
private:
    std::atomic<FirewallAction> default_action_{FirewallAction::PASS};
    // Map to store banned flows (for simulation)
    std::map<FlowKey, FirewallAction> enforced_flows_; 

public:
    // This is where your libpcap/DPDK logic would call to check the fate of a packet.
    PacketDecision get_decision(const uint8_t* packet_data, uint16_t len) override {
        // In a real system, you'd parse the headers here to get FlowKey.
        // For simplicity, we'll just check the default action.
        
        // Example: Drop any packet over 1500 bytes (malformed/jumbo check)
        if (len > 1500) {
            return {FirewallAction::DROP, "JUMBO_PACKET"};
        }

        // TODO: Look up FlowKey in enforced_flows_ map.
        
        return {default_action_.load(), "DEFAULT_POLICY"};
    }
    
    void enforce_flow_policy(FlowKey flow_id, FirewallAction action) override {
        enforced_flows_[flow_id] = action;
        std::cout << "CONTROL-PLANE: Enforced action " << (int)action 
                  << " on flow: " << flow_id << std::endl;
    }

    FirewallAction get_default_action() const override {
        return default_action_.load();
    }
    
    // Setter for control plane updates
    void set_default_action(FirewallAction action) {
        default_action_.store(action);
    }
};

