import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useTheme } from "@/hooks/use-theme";
import { useState } from "react";

export default function Settings() {
  const { theme, setTheme } = useTheme();
  const [apiEndpoint, setApiEndpoint] = useState("http://localhost:8000");
  const [refreshInterval, setRefreshInterval] = useState("30");
  const [alertNotifications, setAlertNotifications] = useState(true);
  const [emailAlerts, setEmailAlerts] = useState(false);
  const [emailAddress, setEmailAddress] = useState("");
  
  return (
    <div className="mt-8 space-y-6">
      <div>
        <h2 className="text-2xl font-semibold">Settings</h2>
        <p className="text-muted-foreground">Configure application preferences</p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Appearance Settings */}
        <Card>
          <CardHeader>
            <CardTitle>Appearance</CardTitle>
            <CardDescription>Customize the application appearance</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <Label htmlFor="theme-mode">Dark Mode</Label>
              <Switch 
                id="theme-mode"
                checked={theme === 'dark'}
                onCheckedChange={(checked) => setTheme(checked ? 'dark' : 'light')}
              />
            </div>
          </CardContent>
        </Card>
        
        {/* API Settings */}
        <Card>
          <CardHeader>
            <CardTitle>API Settings</CardTitle>
            <CardDescription>Configure API and data refresh settings</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="api-endpoint">API Endpoint</Label>
              <Input 
                id="api-endpoint" 
                value={apiEndpoint} 
                onChange={(e) => setApiEndpoint(e.target.value)}
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="refresh-interval">Data Refresh Interval (seconds)</Label>
              <Select value={refreshInterval} onValueChange={setRefreshInterval}>
                <SelectTrigger id="refresh-interval">
                  <SelectValue placeholder="Select refresh interval" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="10">10 seconds</SelectItem>
                  <SelectItem value="30">30 seconds</SelectItem>
                  <SelectItem value="60">1 minute</SelectItem>
                  <SelectItem value="300">5 minutes</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        </Card>
        
        {/* Notification Settings */}
        <Card>
          <CardHeader>
            <CardTitle>Notifications</CardTitle>
            <CardDescription>Configure alert notifications</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <Label htmlFor="browser-notifications">Browser Notifications</Label>
              <Switch 
                id="browser-notifications"
                checked={alertNotifications}
                onCheckedChange={setAlertNotifications}
              />
            </div>
            
            <div className="flex items-center justify-between">
              <Label htmlFor="email-alerts">Email Alerts</Label>
              <Switch 
                id="email-alerts"
                checked={emailAlerts}
                onCheckedChange={setEmailAlerts}
              />
            </div>
            
            {emailAlerts && (
              <div className="space-y-2">
                <Label htmlFor="email-address">Email Address</Label>
                <Input 
                  id="email-address" 
                  type="email" 
                  placeholder="Enter email address"
                  value={emailAddress}
                  onChange={(e) => setEmailAddress(e.target.value)}
                />
              </div>
            )}
          </CardContent>
        </Card>
        
        {/* Security Settings */}
        <Card>
          <CardHeader>
            <CardTitle>Security</CardTitle>
            <CardDescription>Configure security settings</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="session-timeout">Session Timeout (minutes)</Label>
              <Select defaultValue="30">
                <SelectTrigger id="session-timeout">
                  <SelectValue placeholder="Select timeout" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="15">15 minutes</SelectItem>
                  <SelectItem value="30">30 minutes</SelectItem>
                  <SelectItem value="60">1 hour</SelectItem>
                  <SelectItem value="120">2 hours</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <Button className="w-full">Change Password</Button>
          </CardContent>
        </Card>
      </div>
      
      <div className="flex justify-end space-x-2">
        <Button variant="outline">Cancel</Button>
        <Button>Save Changes</Button>
      </div>
    </div>
  );
}
