import { pgTable, text, serial, integer, boolean, timestamp, json, real } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Users table
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

// NetworkTraffic table
export const networkTraffic = pgTable("network_traffic", {
  id: serial("id").primaryKey(),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
  sourceIp: text("source_ip").notNull(),
  destinationIp: text("destination_ip").notNull(),
  protocol: text("protocol").notNull(),
  packetSize: integer("packet_size").notNull(),
  synFlag: boolean("syn_flag").notNull().default(false),
  sourcePort: integer("source_port"),
  destinationPort: integer("destination_port"),
  attackType: text("attack_type"),
  isAttack: boolean("is_attack").notNull().default(false),
});

export const insertNetworkTrafficSchema = createInsertSchema(networkTraffic).omit({
  id: true,
});

export type InsertNetworkTraffic = z.infer<typeof insertNetworkTrafficSchema>;
export type NetworkTraffic = typeof networkTraffic.$inferSelect;

// Alerts table
export const alerts = pgTable("alerts", {
  id: serial("id").primaryKey(),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
  type: text("type").notNull(),
  source: text("source").notNull(),
  target: text("target").notNull(),
  severity: text("severity").notNull(),
  status: text("status").notNull(),
  description: text("description"),
});

export const insertAlertSchema = createInsertSchema(alerts).omit({
  id: true,
});

export type InsertAlert = z.infer<typeof insertAlertSchema>;
export type Alert = typeof alerts.$inferSelect;

// NetworkMetrics table for aggregated data
export const networkMetrics = pgTable("network_metrics", {
  id: serial("id").primaryKey(),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
  trafficVolume: integer("traffic_volume").notNull(),
  packetRate: integer("packet_rate").notNull(),
  synRatio: real("syn_ratio").notNull(),
  sourceEntropy: real("source_entropy").notNull(),
  destinationEntropy: real("destination_entropy").notNull(),
  uniqueSrcIps: integer("unique_src_ips").notNull(),
  uniqueDstIps: integer("unique_dst_ips").notNull(),
  protocolDistribution: json("protocol_distribution").notNull(),
  threatLevel: text("threat_level").notNull(),
});

export const insertNetworkMetricsSchema = createInsertSchema(networkMetrics).omit({
  id: true,
});

export type InsertNetworkMetrics = z.infer<typeof insertNetworkMetricsSchema>;
export type NetworkMetrics = typeof networkMetrics.$inferSelect;

// DashboardMetrics table for simplified dashboard display
export const dashboardMetrics = pgTable("dashboard_metrics", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  value: text("value").notNull(),
  change_percent: real("change_percent"),
  trend: text("trend"),
  created_at: timestamp("created_at").notNull().defaultNow(),
});

export const insertDashboardMetricsSchema = createInsertSchema(dashboardMetrics).omit({
  id: true,
  created_at: true,
});

export type InsertDashboardMetrics = z.infer<typeof insertDashboardMetricsSchema>;
export type DashboardMetrics = typeof dashboardMetrics.$inferSelect;

// TrafficPath table
export const trafficPaths = pgTable("traffic_paths", {
  id: serial("id").primaryKey(),
  pathId: text("path_id").notNull(),
  source: text("source").notNull(),
  destination: text("destination").notNull(),
  hops: text("hops").notNull(),
  trafficVolume: integer("traffic_volume").notNull(),
  status: text("status").notNull(),
});

export const insertTrafficPathSchema = createInsertSchema(trafficPaths).omit({
  id: true,
});

export type InsertTrafficPath = z.infer<typeof insertTrafficPathSchema>;
export type TrafficPath = typeof trafficPaths.$inferSelect;

// NetworkNode table
export const networkNodes = pgTable("network_nodes", {
  id: serial("id").primaryKey(),
  nodeId: text("node_id").notNull().unique(),
  name: text("name").notNull(),
  type: text("type").notNull(),
  x: integer("x").notNull(),
  y: integer("y").notNull(),
  status: text("status"),
});

export const insertNetworkNodeSchema = createInsertSchema(networkNodes).omit({
  id: true,
});

export type InsertNetworkNode = z.infer<typeof insertNetworkNodeSchema>;
export type NetworkNode = typeof networkNodes.$inferSelect;

// NetworkLink table
export const networkLinks = pgTable("network_links", {
  id: serial("id").primaryKey(),
  source: text("source").notNull(),
  target: text("target").notNull(),
  status: text("status"),
});

export const insertNetworkLinkSchema = createInsertSchema(networkLinks).omit({
  id: true,
});

export type InsertNetworkLink = z.infer<typeof insertNetworkLinkSchema>;
export type NetworkLink = typeof networkLinks.$inferSelect;
