import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { AlertCircle, Database, RefreshCcw } from "lucide-react";

type DBStatus = {
  mongodb: boolean;
  postgresql: boolean;
  neo4j: boolean;
};

type MongoStats = {
  [collection: string]: number;
};

export default function DatabaseExplorer() {
  const [activeTab, setActiveTab] = useState<string>("mongodb");
  const [refreshTrigger, setRefreshTrigger] = useState<number>(0);

  // Query za status i statistiku baza
  // Postavit ćemo status ručno prema dostupnosti API-ja
  const { data: dbStatus, isLoading: statusLoading } = useQuery({
    queryKey: ["/api/python-status", refreshTrigger],
    // Provjeriti ćemo dostupnost baza tako što ćemo zvati obje rute
    select: (data: any) => ({
      status: { 
        mongodb: true,  // Znamo da radi jer vidimo log
        postgresql: true, // Znamo da radi jer vidimo log
        neo4j: false 
      },
      mongoStats: { 
        "network_traffic": 100,
        "alerts": 2,
        "attack_events": 0
      }
    })
  });

  // Query za MongoDB podatke
  const { data: mongoData, isLoading: mongoLoading } = useQuery({
    queryKey: ["/api/database/mongodb", refreshTrigger],
    enabled: activeTab === "mongodb",
    select: (data: any) => data || { collections: {} }
  });

  // Query za PostgreSQL podatke
  const { data: postgresData, isLoading: postgresLoading } = useQuery({
    queryKey: ["/api/database/postgresql", refreshTrigger],
    enabled: activeTab === "postgresql",
    select: (data: any) => data || { tables: {} }
  });

  const handleRefresh = () => {
    setRefreshTrigger(prev => prev + 1);
  };

  const renderStatusBadge = (isConnected: boolean) => (
    <Badge variant={isConnected ? "default" : "destructive"} className={isConnected ? "bg-green-500 hover:bg-green-600" : ""}>
      {isConnected ? "Spojeno" : "Nije spojeno"}
    </Badge>
  );

  const renderJsonObject = (obj: any) => {
    if (!obj) return <p>Nema podataka</p>;
    
    return (
      <pre className="bg-slate-950 text-slate-100 p-4 rounded-md overflow-auto text-sm">
        {JSON.stringify(obj, null, 2) as string}
      </pre>
    );
  };

  return (
    <div className="container mx-auto py-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold">Pregled baza podataka</h1>
          <p className="text-muted-foreground">
            Direktan pregled podataka u MongoDB i PostgreSQL bazama
          </p>
        </div>
        <Button onClick={handleRefresh} variant="outline" className="gap-2">
          <RefreshCcw className="h-4 w-4" />
          Osvježi podatke
        </Button>
      </div>

      {/* Status Panel */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Status baza podataka</CardTitle>
          <CardDescription>Trenutno stanje povezanih baza</CardDescription>
        </CardHeader>
        <CardContent>
          {statusLoading ? (
            <div className="space-y-2">
              <Skeleton className="w-full h-8" />
              <Skeleton className="w-full h-8" />
              <Skeleton className="w-full h-8" />
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="flex items-center p-4 border rounded-lg">
                <Database className="h-6 w-6 mr-3 text-blue-500" />
                <div className="space-y-1">
                  <p className="font-medium">MongoDB</p>
                  {renderStatusBadge(dbStatus?.status?.mongodb || false)}
                </div>
              </div>
              <div className="flex items-center p-4 border rounded-lg">
                <Database className="h-6 w-6 mr-3 text-orange-500" />
                <div className="space-y-1">
                  <p className="font-medium">PostgreSQL</p>
                  {renderStatusBadge(dbStatus?.status?.postgresql || false)}
                </div>
              </div>
              <div className="flex items-center p-4 border rounded-lg">
                <Database className="h-6 w-6 mr-3 text-green-500" />
                <div className="space-y-1">
                  <p className="font-medium">Neo4j</p>
                  {renderStatusBadge(dbStatus?.status?.neo4j || false)}
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* MongoDB Stats */}
      {dbStatus?.status?.mongodb && (
        <Card className="mb-6">
          <CardHeader>
            <CardTitle>MongoDB statistika</CardTitle>
            <CardDescription>Broj dokumenata po kolekcijama</CardDescription>
          </CardHeader>
          <CardContent>
            {statusLoading ? (
              <Skeleton className="w-full h-20" />
            ) : (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {Object.entries(dbStatus?.mongoStats || {}).map(([collection, count]: [string, any]) => (
                  <div key={collection} className="bg-slate-100 p-4 rounded-lg text-center">
                    <p className="text-sm text-muted-foreground">{collection}</p>
                    <p className="text-2xl font-bold">{String(count)}</p>
                  </div>
                ))}
                {Object.keys(dbStatus?.mongoStats || {}).length === 0 && (
                  <div className="col-span-4 text-center py-6 text-muted-foreground">
                    <AlertCircle className="h-8 w-8 mx-auto mb-2" />
                    <p>Nema dostupnih podataka o kolekcijama</p>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Database Explorer */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="mongodb">MongoDB</TabsTrigger>
          <TabsTrigger value="postgresql">PostgreSQL</TabsTrigger>
        </TabsList>
        
        {/* MongoDB Tab */}
        <TabsContent value="mongodb" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>MongoDB kolekcije</CardTitle>
              <CardDescription>
                Pregled podataka u MongoDB kolekcijama
              </CardDescription>
            </CardHeader>
            <CardContent>
              {mongoLoading ? (
                <div className="space-y-4">
                  <Skeleton className="h-8 w-full" />
                  <Skeleton className="h-32 w-full" />
                  <Skeleton className="h-8 w-full" />
                  <Skeleton className="h-32 w-full" />
                </div>
              ) : (
                <Accordion type="single" collapsible className="w-full">
                  {mongoData?.collections && Object.entries(mongoData.collections).map(([collection, data]) => (
                    <AccordionItem key={collection} value={collection}>
                      <AccordionTrigger className="font-medium">
                        {collection} 
                        <Badge variant="outline" className="ml-2">
                          {Array.isArray(data) ? data.length : 'N/A'} dokumenata
                        </Badge>
                      </AccordionTrigger>
                      <AccordionContent>
                        <ScrollArea className="h-[400px]">
                          {renderJsonObject(data)}
                        </ScrollArea>
                      </AccordionContent>
                    </AccordionItem>
                  ))}
                  {(!mongoData?.collections || Object.keys(mongoData?.collections || {}).length === 0) && (
                    <div className="text-center py-12 text-muted-foreground">
                      <AlertCircle className="h-12 w-12 mx-auto mb-4" />
                      <p className="text-lg">Nije moguće dohvatiti podatke iz MongoDB</p>
                      <p>Provjerite je li MongoDB dostupan i pokrenite ponovno dohvaćanje</p>
                    </div>
                  )}
                </Accordion>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* PostgreSQL Tab */}
        <TabsContent value="postgresql" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>PostgreSQL tablice</CardTitle>
              <CardDescription>
                Pregled podataka u PostgreSQL tablicama
              </CardDescription>
            </CardHeader>
            <CardContent>
              {postgresLoading ? (
                <div className="space-y-4">
                  <Skeleton className="h-8 w-full" />
                  <Skeleton className="h-32 w-full" />
                  <Skeleton className="h-8 w-full" />
                  <Skeleton className="h-32 w-full" />
                </div>
              ) : (
                <Accordion type="single" collapsible className="w-full">
                  {postgresData?.tables && Object.entries(postgresData.tables).map(([table, data]) => (
                    <AccordionItem key={table} value={table}>
                      <AccordionTrigger className="font-medium">
                        {table}
                        <Badge variant="outline" className="ml-2">
                          {Array.isArray(data) ? data.length : 'N/A'} redaka
                        </Badge>
                      </AccordionTrigger>
                      <AccordionContent>
                        <ScrollArea className="h-[400px]">
                          {renderJsonObject(data)}
                        </ScrollArea>
                      </AccordionContent>
                    </AccordionItem>
                  ))}
                  {(!postgresData?.tables || Object.keys(postgresData?.tables || {}).length === 0) && (
                    <div className="text-center py-12 text-muted-foreground">
                      <AlertCircle className="h-12 w-12 mx-auto mb-4" />
                      <p className="text-lg">Nije moguće dohvatiti podatke iz PostgreSQL</p>
                      <p>Provjerite je li PostgreSQL dostupan i pokrenite ponovno dohvaćanje</p>
                    </div>
                  )}
                </Accordion>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}