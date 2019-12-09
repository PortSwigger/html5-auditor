package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
//import java.io.PrintWriter;

/**
 * demo this on http://html5demos.com Purpose: during assessments, flag those
 * HTML5 practices that should be justified - sometimes bad practices creep in
 * @author clojureboy
 * @TODO Add CORS checks, maybe (but CORS is more service than markup)
 */

public class BurpExtender implements IBurpExtender, IScannerCheck {
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	//private PrintWriter stdout;
	private List<HTML5Worry> html5worries = new ArrayList<HTML5Worry>();

	private static final String LOCAL_STORAGE_BACKGROUND = "HTML5 'localStorage' allows pages to persistently store data on a user's device, facilitating cross window exchange of information and managing bits of state on the client.  You may see it as localStorage.setItem(), or .getItem(), or the shortcut version, localStorage.keyName.  While local storage on the client is useful, this assumes the user endpoint can be trusted.  In mission-critical applications, it may be more secure to manage all state on the server side.";
	private static final String LOCAL_STORAGE_REMEDIATION = "Discuss with developers if possible, to determine if there is a legitimate reason for storing data on a user's endpoint.  The non-persistent sessionStorage object may be a safer alternative to localStorage, if state must be stored on the client.";
	private static final String SESSION_STORAGE_BACKGROUND = "HTML5 'sessionStorage' allows pages to store data for the duration of the session on a user's device, facilitating cross window exchange of information and managing bits of state on the client.  You may see it as sessionStorage.setItem(), sessionStorage.getItem(), or the shortcut version sessionStorage.keyName.  While useful, and safer than the persistent 'localStorage' feature, this assumes the user endpoint can be trusted.  In mission-critical applications, it may be more secure to manage all state on the server side.";
	private static final String SESSION_STORAGE_REMEDIATION = "Discuss with developers if possible, to determine if there is a legitimate reason for storing data on a user's endpoint.  If there is any doubt about the trustiworthiness of potential clients, consider storing only the session cookie with the client, and keeping all other state on the server.";
	private static final String GEO_GETLOC_BACKGROUND = "HTML5 can request a user's current geographical location.  Although generally the user must grant access for the request to succeed, this functionality takes away some user anonymity, and users may be accustomed to granting permissions without much thought.";
	private static final String GEO_WATCH_BACKGROUND = "HTML5 can request to follow ('watch') a user's geographical location.  Although generally the user must grant access for the request to succeed, this functionality takes away some user anonymity, and users may be accustomed to granting permissions without much thought.  Some legal jurisdictions may be sensitive to this sort of user tracking.";
	private static final String GEO_REMEDIATION = "Determine if the site has a legitimate need to know a user's location. If possible, discuss with developers if the user is appropriately warned.";
	private static final String CLIENT_CACHE_BACKGROUND = "HTML5 allows site designers to instruct browsers to keep a cache of specified files. While this reduces network utilization and allows offline browsing, it can potentially infringe upon user privacy and depending on the cached contents, may leave residue (such as personal financial data) on the endpoint device. Also, if the user has been on an untrusted network, the cached version of pages may be malicious ones.";
	private static final String CLIENT_CACHE_REMEDIATION = "Determine if the site has a legitimate need to enforce a cached copy on a user's browser. If possible, discuss with developers if the use case and convenience warrants the impact on user privacy and regulatory risks.";
	private static final String WEB_SOCKET_BACKGROUND = "Web sockets allow bi-directional communiction between client and server.  However, the default protocol scheme of ws:// has unencrypted traffic going over port 80.  This is potentially vulnerable to sniffing (observing the data) and to man-in-the-middle attacks (observing and/or altering the data)";
	private static final String WEB_SOCKET_REMEDIATION = "Discuss with developers if the data security needs of the web socket warrant tunneling within SSL, via the HTML5 protocol scheme 'wss://' ";

	public BurpExtender() {

		html5worries.add(new HTML5Worry("localStorage.", "HTML5 concern: client local storage", "_detail_", "Information",
				LOCAL_STORAGE_BACKGROUND, LOCAL_STORAGE_REMEDIATION));

		html5worries.add(new HTML5Worry("sessionStorage.", "HTML5 concern: client session storage", "_detail_", "Information",
				SESSION_STORAGE_BACKGROUND, SESSION_STORAGE_REMEDIATION));

		html5worries.add(new HTML5Worry("location.getCurrentPosition(", "HTML5 concern: geolocation", "_detail_", "Information",
				GEO_GETLOC_BACKGROUND, GEO_REMEDIATION));

		html5worries.add(new HTML5Worry("location.watchPosition(", "HTML5 concern: geolocation", "_detail_", "Information",
				GEO_WATCH_BACKGROUND, GEO_REMEDIATION));

		html5worries.add(new HTML5Worry("<html manifest=\"", "HTML5 concern: client cache", "_detail_", "Information",
				CLIENT_CACHE_BACKGROUND, CLIENT_CACHE_REMEDIATION));

		html5worries.add(new HTML5Worry(" ws://", "HTML5 concern: insecure web sockets", "_detail_", "Information", WEB_SOCKET_BACKGROUND,
				WEB_SOCKET_REMEDIATION));

	}

	//
	// implement IBurpExtender
	//

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		// keep a reference to our callbacks object
		this.callbacks = callbacks;

		// obtain an extension helpers object
		helpers = callbacks.getHelpers();

		// set our extension name
		callbacks.setExtensionName("HTML5 auditor");

		// register ourselves as a custom scanner check
		callbacks.registerScannerCheck(this);

		// obtain our output stream, for debug only
		//stdout = new PrintWriter(callbacks.getStdout(), true);
		//stdout.println("html5audit .. ready");
	}

	// helper method to search a response for occurrences of a literal match
	// string and return a list of start/end offsets
	private List<int[]> getMatches(byte[] response, byte[] match) {
		List<int[]> matches = new ArrayList<int[]>();

		int start = 0;
		while (start < response.length) {
			start = helpers.indexOf(response, match, true, start, response.length);
			if (start == -1)
				break;
			matches.add(new int[] { start, start + match.length });
			start += match.length;
		}

		return matches;
	}

	/**
	 * implment IScannerCheck
	 */

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		List<IScanIssue> issues = new ArrayList<>();
		Iterable<HTML5Worry> worries = html5worries;

		for (HTML5Worry worry : worries) {
			byte[] GREP_STRING = worry.getGrepString().getBytes();

			// look for matches of our passive check grep string
			List<int[]> matches = getMatches(baseRequestResponse.getResponse(), GREP_STRING);
			if (matches.size() > 0) {
				issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(), helpers.analyzeRequest(
						baseRequestResponse).getUrl(), new IHttpRequestResponse[] { callbacks.applyMarkers(
						baseRequestResponse, null, matches) }, worry.getName(), "The response contains the string: "
						+ helpers.bytesToString(GREP_STRING), worry.getSeverity(), worry.getBackground(), worry
						.getRemediation()));
			}

		}
		return issues;
	}

	// just invoke passive scan for now
	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
		return doPassiveScan(baseRequestResponse);
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		// This method is called when multiple issues are reported for the same
		// URL
		// path by the same extension-provided check. The value we return from
		// this
		// method determines how/whether Burp consolidates the multiple issues
		// to prevent duplication
		//
		// Since the issue name is sufficient to identify our issues as
		// different,
		// if both issues have the same name, only report the existing issue
		// otherwise report both issues
		if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
			return -1;
		else
			return 0;
	}
}

/**
 * Convenience object, holds Burpsuite info for each HTML5 worry
 * 
 * @author thompsco
 */
class HTML5Worry {
	private String html5grepString;
	private String name;
	private String detail;
	private String severity;
	private String background;
	private String remediation;

	public HTML5Worry(String grepStringArg, String nameArg, String detailArg, String severityArg, String backgroundArg,
			String remediationArg) {
		html5grepString = grepStringArg;
		name = nameArg;
		detail = detailArg;
		severity = severityArg;
		background = backgroundArg;
		remediation = remediationArg;
	}

	public String getGrepString() {
		return html5grepString;
	}

	public String getName() {
		return name;
	}

	public String getDetail() {
		return detail;
	}

	public String getSeverity() {
		return severity;
	}

	public String getBackground() {
		return background;
	}

	public String getRemediation() {
		return remediation;
	}
}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue {
	private IHttpService httpService;
	private URL url;
	private IHttpRequestResponse[] httpMessages;
	private String name;
	private String detail;
	private String severity;
	private String background;
	private String remediation;

	public CustomScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name,
			String detail, String severity, String background, String remediation) {
		this.httpService = httpService;
		this.url = url;
		this.httpMessages = httpMessages;
		this.name = name;
		this.detail = detail;
		this.severity = severity;
		this.background = background;
		this.remediation = remediation;
	}

	@Override
	public URL getUrl() {
		return url;
	}

	@Override
	public String getIssueName() {
		return name;
	}

	@Override
	public int getIssueType() {
		return 0;
	}

	@Override
	public String getSeverity() {
		return severity;
	}

	@Override
	public String getConfidence() {
		return "Firm";
	}

	@Override
	public String getIssueBackground() {
		return background;
	}

	@Override
	public String getRemediationBackground() {
		return remediation;
	}

	@Override
	public String getIssueDetail() {
		return detail;
	}

	@Override
	public String getRemediationDetail() {
		return null;
	}

	@Override
	public IHttpRequestResponse[] getHttpMessages() {
		return httpMessages;
	}

	@Override
	public IHttpService getHttpService() {
		return httpService;
	}

}
