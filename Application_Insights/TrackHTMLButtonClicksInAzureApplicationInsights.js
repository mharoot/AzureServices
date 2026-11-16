/*
Track Button Clicks with Application Insights
you can track HTML button clicks in an Office Add-in using Azure Application Insights, but it requires manual instrumentation.

Add Application Insights to your Office Add-in
Include the Application Insights JavaScript SDK in your add-in's HTML or JavaScript files.

View Events in Azure Portal
Go to your Application Insights resource.
Use Analytics or Live Metrics to query and visualize button click events.

To track user ID, Office context, and timestamp in your Office Add-in using Azure Application Insights, along with event batching or throttling, here's a complete guide:
*/



/*
1. Initialize Application Insights with Context
Use the SDK and enrich telemetry with custom properties:
*/
const appInsights = window.appInsights || require("applicationinsights-web");

appInsights.downloadAndSetup({
  instrumentationKey: "YOUR_INSTRUMENTATION_KEY",
  enableAutoRouteTracking: true,
});

// Set user ID (e.g., from Office context or login)
appInsights.setAuthenticatedUserContext("user@example.com");

// Add global properties
appInsights.addTelemetryInitializer((envelope) => {
  const data = envelope.data;
  const baseData = data.baseData;

  // Add Office context
  baseData.properties = {
    ...baseData.properties,
    officeHost: Office.context.host, // e.g., Word, Excel
    officePlatform: Office.context.platform, // e.g., OfficeOnline, Desktop
    timestamp: new Date().toISOString(),
  };
});


/*
2. Track Button Clicks with Custom Events
Attach listeners to buttons and send enriched telemetry:
*/
document.getElementById("myButton").addEventListener("click", () => {
  appInsights.trackEvent({
    name: "ButtonClicked",
    properties: {
      buttonId: "myButton",
      location: "TaskPane",
      timestamp: new Date().toISOString(),
    }
  });
});


/*
3. Batching and Throttling Events
The SDK handles batching automatically by default. To throttle or limit event frequency manually:
*/
let lastClickTime = 0;
const throttleInterval = 3000; // 3 seconds

document.getElementById("myButton").addEventListener("click", () => {
  const now = Date.now();
  if (now - lastClickTime > throttleInterval) {
    lastClickTime = now;
    appInsights.trackEvent({
      name: "ThrottledButtonClick",
      properties: {
        buttonId: "myButton",
        timestamp: new Date().toISOString(),
      }
    });
  }
});


/*
4. Viewing in Azure Portal

Go to your Application Insights resource.
Use Log Analytics with queries like:

customEvents
| where name == "ButtonClicked"
| project timestamp, name, customDimensions
*/



