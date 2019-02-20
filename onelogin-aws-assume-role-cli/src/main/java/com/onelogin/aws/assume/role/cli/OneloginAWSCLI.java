package com.onelogin.aws.assume.role.cli;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.profile.ProfilesConfigFileWriter;
import com.amazonaws.auth.profile.internal.Profile;
import com.amazonaws.auth.profile.internal.ProfileKeyConstants;
import com.amazonaws.profile.path.AwsProfileFileLocationProvider;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithSAMLRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithSAMLResult;
import com.amazonaws.services.securitytoken.model.AssumedRoleUser;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.sdk.conn.Client;
import com.onelogin.sdk.model.Device;
import com.onelogin.sdk.model.MFA;
import com.onelogin.sdk.model.SAMLEndpointResponse;

public class OneloginAWSCLI {

	private static int time = 45;
	private static int loop = 1;
	private static String profileName = null;
	private static File file = null;
	private static String oneloginUsernameOrEmail = null;
	private static String appId = null;
	private static String oneloginDomain = null;
	private static String awsRegion = null;
	private static String awsAccount = null;
	private static String awsRole = null;
	private static String ip = null;
	private static Boolean scan = null;

	public static Boolean commandParser(final String[] commandLineArguments) {
		final CommandLineParser cmd = new DefaultParser();
		final Options options = buildOptions();
		CommandLine commandLine;
		try {
			commandLine = cmd.parse(options, commandLineArguments);
			String value;

			if (commandLine.hasOption("help")) {
				HelpFormatter hf = new HelpFormatter();
				hf.printHelp("onelogin-aws-cli.jar [options]", options);
				System.out.println("");
				return false;
			}

			if (commandLine.hasOption("time")) {
				value = commandLine.getOptionValue("time");
				if (value != null && !value.isEmpty()) {
					time = Integer.parseInt(value);
				}
				if (time < 15 ) {
					time = 15;
				}
				if (time > 720 ) {
					time = 720;
				}
			}
			if (commandLine.hasOption("loop")) {
				value = commandLine.getOptionValue("loop");
				if (value != null && !value.isEmpty()) {
					loop = Integer.parseInt(value);
				}
			}
			if (commandLine.hasOption("profile")) {
				value = commandLine.getOptionValue("profile");
				if (value != null && !value.isEmpty()) {
					profileName = value;
				} else {
					profileName = "default";
				}
			}
			if (commandLine.hasOption("file")) {
				value = commandLine.getOptionValue("file");
				if (value != null && !value.isEmpty()) {
					file = new File(value);
				}
			}

			if (commandLine.hasOption("username")) {
				value = commandLine.getOptionValue("username");
				if (value != null && !value.isEmpty()) {
					oneloginUsernameOrEmail = value;
				}
			}

			if (commandLine.hasOption("subdomain")) {
				value = commandLine.getOptionValue("subdomain");
				if (value != null && !value.isEmpty()) {
					oneloginDomain = value;
				}
			}

			if (commandLine.hasOption("appid")) {
				value = commandLine.getOptionValue("appid");
				if (value != null && !value.isEmpty()) {
					appId = value;
				}
			}

			if (commandLine.hasOption("region")) {
				value = commandLine.getOptionValue("region");
				if (value != null && !value.isEmpty()) {
					awsRegion = value;
				}
			}

			if (commandLine.hasOption("account")) {
				if (commandLine.hasOption("role")) {
					value = commandLine.getOptionValue("account");
					if (value != null && !value.isEmpty()) {
						awsAccount = value;
					}	
				}
				else {
					throw new ParseException(" : Account option requires 'role' to be specified");
				}
			}

			if (commandLine.hasOption("role")) {
				if (commandLine.hasOption("account")) {
					value = commandLine.getOptionValue("role");
					if (value != null && !value.isEmpty()) {
						awsRole = value;
					}	
				}
				else {
					throw new ParseException(" : Role option requires 'account' to be specified");
				}
			}

			scan = commandLine.hasOption("scan");

			return true;
		}
		catch (ParseException parseException) {
			System.err.println("Encountered exception while parsing" + parseException.getMessage());
			return false;
		}
	}

	public static Options buildOptions() {
		final Options options = new Options();
		
		options.addOption("h", "help", false, "Show the help guide");
		options.addOption("t", "time", true, "Sleep time between iterations, in minutes  [15-720 min]");
		options.addOption("l", "loop", true, "Number of iterations");
		options.addOption("p", "profile", true, "Save temporary AWS credentials using that profile name");
		options.addOption("f", "file", true, "Set a custom path to save the AWS credentials. (if not used, default AWS path is used)");
		options.addOption("r", "region", true, "Set the AWS region.");
		options.addOption("a", "appid", true, "Set AWS App ID.");
		options.addOption("d", "subdomain", true, "Onelogin Instance Sub Domain.");
		options.addOption("u", "username", true, "Onelogin username.");
		options.addOption("c", "account", true, "AWS Account to automatically map to.  Requires 'role'.");
		options.addOption("o", "role", true, "AWS Role to automatically map to.  Requires 'account'.");
		options.addOption("s", "scan", false, "Scan all available accounts / roles and rotate keys, default to AWS profile mode and use AWS alias as the profile name");

		return options;
	}

	public static void main(String[] commandLineArguments) throws Exception {

		System.out.println("\nOneLogin AWS Assume Role Tool\n");

		if(!commandParser(commandLineArguments)){
			return;
		}

		// OneLogin Java SDK Client
		Client olClient = new Client();		
		String ip = olClient.getIP();
		olClient.getAccessToken();
		Scanner scanner = new Scanner(System.in);
		try {
			String oneloginPassword = null;
			String samlResponse;

			Map<String, String> mfaVerifyInfo = null;
			Map<String, Object> result;

			String roleArn = null;
			String principalArn = null;
			String defaultAWSRegion = Regions.DEFAULT_REGION.getName();

			for (int i = 0; i < loop; i++) {
				if (i == 0) {
					// Capture OneLogin Account Details
					System.out.print("OneLogin Username: ");
					if (oneloginUsernameOrEmail == null) {
						oneloginUsernameOrEmail = scanner.next();
					} else{
						System.out.println(oneloginUsernameOrEmail);
					}

					System.out.print("OneLogin Password: ");
					try {
						oneloginPassword = String.valueOf(System.console().readPassword());
					} catch (Exception e) {
						oneloginPassword = scanner.next();
					}
					System.out.print("AWS App ID: ");
					if (appId == null) {
						appId = scanner.next();
					} else {
							System.out.println(appId);
					}

					System.out.print("Onelogin Instance Sub Domain: ");
					if (oneloginDomain == null) {
						oneloginDomain = scanner.next();
					} else {
						System.out.println(oneloginDomain);
					}
				} else {
					System.out.println("Pausing for " + time + " minutes...");
					TimeUnit.MINUTES.sleep(time);
				}

				result = getSamlResponse(olClient, scanner, oneloginUsernameOrEmail, oneloginPassword, appId, oneloginDomain, mfaVerifyInfo, ip);
				mfaVerifyInfo = (Map<String, String>) result.get("mfaVerifyInfo");
				samlResponse = (String) result.get("samlResponse");

				Integer sessionDurationSeconds = 3600;
				HashMap<String, List<String>> attributes = getSamlResponseAttributes(samlResponse);

				if (attributes.containsKey("https://aws.amazon.com/SAML/Attributes/SessionDuration")) {
					List<String> sessionDurationData = attributes.get("https://aws.amazon.com/SAML/Attributes/SessionDuration");
					sessionDurationSeconds = Integer.parseInt(sessionDurationData.get(0));
				}

				if (scan) {

					if (!attributes.containsKey("https://aws.amazon.com/SAML/Attributes/Role")) {
						System.out.print("SAMLResponse from Identity Provider does not contain AWS Role info");
						System.exit(0);
					} else {
						List<String> roleData = attributes.get("https://aws.amazon.com/SAML/Attributes/Role");
						HashMap<String, String> aliasMap = getAliasMap(samlResponse);

						for (int j = 0; j < roleData.size(); j++) {
							String role = roleData.get(j);
							String[] selectedRoleData = role.split(",");

							String[] roleInfo = roleData.get(j).split(":");
							String accountId = roleInfo[4];

							roleArn = selectedRoleData[0];
							principalArn = selectedRoleData[1];
							profileName = aliasMap.get(accountId);
							
							assumeRole(principalArn, roleArn, samlResponse, awsRegion, profileName, file, sessionDurationSeconds);
						}
					}
				}
				else {
					if (i == 0) {
						if (!attributes.containsKey("https://aws.amazon.com/SAML/Attributes/Role")) {
							System.out.print("SAMLResponse from Identity Provider does not contain AWS Role info");
							System.exit(0);
						} else {
							String selectedRole = "";
							List<String> roleData = attributes.get("https://aws.amazon.com/SAML/Attributes/Role");
							if (awsAccount != null && awsRole != null) {
								for (int j = 0; j < roleData.size(); j++) {
									String role = roleData.get(j);
									String[] roleInfo = role.split(":");
									String accountId = roleInfo[4];
									String roleName = roleInfo[5].replace("role/", "").replace(",arn", "");
									if (awsAccount.equals(accountId) && awsRole.equals(roleName)) {
										selectedRole = role;
										break;
									}
								}
								if (selectedRole.isEmpty()) {
									System.out.print("Unable to automatically map provided AWS Account / Role");
									System.exit(0);	
								}
							} else if (roleData.size() == 1) {
								String[] roleInfo = roleData.get(0).split(":");
								String accountId = roleInfo[4];
								String roleName = roleInfo[5].replace("role/", "");
								System.out.println("Role selected: " + roleName + " (Account " + accountId + ")");
								selectedRole = roleData.get(0);
							} else if (roleData.size() > 1) {
								HashMap<String, String> aliasMap = getAliasMap(samlResponse);
								System.out.println("\nAvailable AWS Roles");
								System.out.println("-----------------------------------------------------------------------");
								for (int j = 0; j < roleData.size(); j++) {
									String[] roleInfo = roleData.get(j).split(":");
									String accountId = roleInfo[4];
									String roleName = roleInfo[5].replace("role/", "").replace(",arn", "");
									String alias = aliasMap.get(accountId);
									System.out.println(j + " | " + alias + " | " + roleName + " | " + accountId);
								}
								System.out.println("-----------------------------------------------------------------------");
								System.out.print("Select the desired Role [0-" + (roleData.size() - 1) + "]: ");
								Integer roleSelection = Integer.valueOf(scanner.next());
								selectedRole = roleData.get(roleSelection);
							} else {
								System.out.print("SAMLResponse from Identity Provider does not contain available AWS Role for this user");
								System.exit(0);
							}
	
							if (!selectedRole.isEmpty()) {
								String[] selectedRoleData = selectedRole.split(",");
								roleArn = selectedRoleData[0];
								principalArn = selectedRoleData[1];
							}
						}
					}
		
					if (i == 0) {
						// AWS REGION
						if (awsRegion == null) {
							System.out.print("AWS Region (" + defaultAWSRegion + "): ");
							awsRegion = scanner.next();
							if (awsRegion.isEmpty() || awsRegion.equals("-")) {
								awsRegion = defaultAWSRegion;
							}
						}else {
							System.out.print("AWS Region: " + awsRegion);
						}
					}
					
					assumeRole(principalArn, roleArn, samlResponse, awsRegion, profileName, file, sessionDurationSeconds);
				}

				if (loop > (i+1)) {
					System.out.println("This process will regenerate credentials " + (loop - (i+1)) + " more times.\n");
					System.out.println("Press Ctrl + C to exit");
				}
			}
		} finally {
			scanner.close();
		}
	}

	public static void assumeRole(String principalArn, String roleArn, String samlResponse, String awsRegion, String profileName, File file, Integer sessionDurationSeconds) throws Exception {
	
		BasicAWSCredentials awsCredentials = new BasicAWSCredentials("", "");
	
		AWSSecurityTokenServiceClientBuilder stsBuilder = AWSSecurityTokenServiceClientBuilder.standard();

		AWSSecurityTokenService stsClient = stsBuilder
			.withRegion(awsRegion)
			.withCredentials(new AWSStaticCredentialsProvider(awsCredentials))
			.build();

		AssumeRoleWithSAMLRequest assumeRoleWithSAMLRequest = new AssumeRoleWithSAMLRequest()
				.withDurationSeconds(sessionDurationSeconds)
				.withPrincipalArn(principalArn)
				.withRoleArn(roleArn)
				.withSAMLAssertion(samlResponse);
				
		AssumeRoleWithSAMLResult assumeRoleWithSAMLResult = stsClient
				.assumeRoleWithSAML(assumeRoleWithSAMLRequest);
		Credentials stsCredentials = assumeRoleWithSAMLResult.getCredentials();
		AssumedRoleUser assumedRoleUser = assumeRoleWithSAMLResult.getAssumedRoleUser();

		if (profileName == null && file == null) {
			String action = "export";
			if (System.getProperty("os.name").toLowerCase().contains("win")) {
				action = "set";
			}
			System.out.println("\n-----------------------------------------------------------------------\n");
			System.out.println("Success!\n");
			System.out.println("Assumed Role User: " + assumedRoleUser.getArn() + "\n");
			System.out.println("Temporary AWS Credentials Granted via OneLogin\n");
			System.out.println("Copy/Paste to set these as environment variables\n");
			System.out.println("-----------------------------------------------------------------------\n");

			System.out.println(action + " AWS_SESSION_TOKEN=" + stsCredentials.getSessionToken());
			System.out.println();
			System.out.println(action + " AWS_ACCESS_KEY_ID=" + stsCredentials.getAccessKeyId());
			System.out.println();
			System.out.println(action + " AWS_SECRET_ACCESS_KEY=" + stsCredentials.getSecretAccessKey());
			System.out.println();
		} else {
			if (file == null) {
				file = AwsProfileFileLocationProvider.DEFAULT_CREDENTIALS_LOCATION_PROVIDER.getLocation();
			}
			if (profileName == null) {
				profileName = "default";
			}

			Map<String, String> properties = new HashMap<String, String>();
			properties.put(ProfileKeyConstants.AWS_ACCESS_KEY_ID, stsCredentials.getAccessKeyId());
			properties.put(ProfileKeyConstants.AWS_SECRET_ACCESS_KEY, stsCredentials.getSecretAccessKey());
			properties.put(ProfileKeyConstants.AWS_SESSION_TOKEN, stsCredentials.getSessionToken());
			properties.put(ProfileKeyConstants.REGION, awsRegion);

			ProfilesConfigFileWriter.modifyOneProfile(file, profileName, new Profile(profileName, properties, null));

			System.out.println("\n-----------------------------------------------------------------------");
			System.out.println("Success!\n");
			System.out.println("Temporary AWS Credentials Granted via OneLogin\n");
			System.out.println("Updated AWS profile '" + profileName + "' located at " + file.getAbsolutePath());
		}

	}

	public static HashMap<String, List<String>> getSamlResponseAttributes(String samlResponse) throws Exception {
		HttpRequest simulatedRequest = new HttpRequest("http://example.com");
		simulatedRequest = simulatedRequest.addParameter("SAMLResponse", samlResponse);
		SamlResponse samlResponseObj = new SamlResponse(null, simulatedRequest);
		return samlResponseObj.getAttributes();
	}

	public static HashMap<String, String> getAliasMap(String samlResponse) throws Exception {
		System.out.println("Evaluating AWS Alias Map");

		String urlParameters = URLEncoder.encode("SAMLResponse", "UTF-8") + "=" + URLEncoder.encode(samlResponse, "UTF-8");
		String request = "https://signin.aws.amazon.com/saml";
		
		URL url = new URL(request);
		
		HttpURLConnection conn= (HttpURLConnection)url.openConnection();           
		
		conn.setDoOutput(true);
		conn.setInstanceFollowRedirects(false);
		conn.setRequestMethod("POST");
		conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded"); 
		conn.setUseCaches(false);

		OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
		wr.write(urlParameters);
		wr.flush();

		BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
		StringBuilder sb = new StringBuilder();
		String output;
		while ((output = br.readLine()) != null) {
			sb.append(output);
		}

		String htmlString = sb.toString();
		Document doc = Jsoup.parse(htmlString);
		HashMap<String, String> aliasMap = new HashMap<String,String>();
		List<String> links = doc.select(".saml-account-name").eachText();
		for(String item : links){
			String[] bits = item.split(" ");
			aliasMap.put(bits[2].replace("(", "").replace(")", ""), bits[1]);
		}
		return aliasMap;
	}

	public static Map<String, Object> getSamlResponse(Client olClient, Scanner scanner, String oneloginUsernameOrEmail,
			String oneloginPassword, String appId, String oneloginDomain, Map<String, String> mfaVerifyInfo, String ip)
			throws Exception {
		String otpToken, stateToken;
		Device deviceSelection;
		Long deviceId;
		String deviceIdStr = null;
		Map<String, Object> result = new HashMap<String, Object>();

		SAMLEndpointResponse samlEndpointResponse = olClient.getSAMLAssertion(oneloginUsernameOrEmail, oneloginPassword,
				appId, oneloginDomain, ip);
		String status = samlEndpointResponse.getType();
		while (status.equals("pending")) {
			TimeUnit.SECONDS.sleep(30);
			samlEndpointResponse = olClient.getSAMLAssertion(oneloginUsernameOrEmail, oneloginPassword, appId,
					oneloginDomain, ip);
			status = samlEndpointResponse.getType();
		}
		String samlResponse = null;
		if (status.equals("success")) {
			if (samlEndpointResponse.getMFA() != null) {
				MFA mfa = samlEndpointResponse.getMFA();
				List<Device> devices = mfa.getDevices();

				if (mfaVerifyInfo == null) {
					System.out.println();
					System.out.println("MFA Required");
					System.out.println("Authenticate using one of these devices:");
				} else {
					deviceIdStr = mfaVerifyInfo.get("deviceId");
					if (!checkDeviceExists(devices, Long.parseLong(deviceIdStr))) {
						System.out.println();
						System.out.println("The device selected with ID " + deviceIdStr + " is not available anymore");
						System.out.println("Those are the devices available now:");
						mfaVerifyInfo = null;
					}
				}

				if (mfaVerifyInfo == null) {
					System.out.println("-----------------------------------------------------------------------");
					Device device;
					Integer deviceInput;
					if (devices.size() == 1) {
						deviceInput = 0;
					} else {
						for (int i = 0; i < devices.size(); i++) {
							device = devices.get(i);
							System.out.println(" " + i + " | " + device.getType());
						}
						System.out.println("-----------------------------------------------------------------------");
						System.out.print("\nSelect the desired MFA Device [0-" + (devices.size() - 1) + "]: ");
						deviceInput = Integer.valueOf(scanner.next());
					}

					deviceSelection = devices.get(deviceInput);
					deviceId = deviceSelection.getID();
					deviceIdStr = deviceId.toString();

					System.out.print("Enter the OTP Token for " + deviceSelection.getType() + ": ");
					otpToken = scanner.next();
					stateToken = mfa.getStateToken();
					mfaVerifyInfo = new HashMap<String, String>();
					mfaVerifyInfo.put("otpToken", otpToken);
					mfaVerifyInfo.put("stateToken", stateToken);
				} else {
					otpToken = mfaVerifyInfo.get("otpToken");
					stateToken = mfaVerifyInfo.get("stateToken");
				}
				result = verifyToken(olClient, scanner, appId,
						deviceIdStr, stateToken, otpToken, mfaVerifyInfo);
				
			} else {
				samlResponse = samlEndpointResponse.getSAMLResponse();
				result.put("samlResponse", samlResponse);
				result.put("mfaVerifyInfo", mfaVerifyInfo);
			}
		}
		return result;
	}

	public static Map<String, Object> getSamlResponse(Client olClient, Scanner scanner, String oneloginUsernameOrEmail,
			String oneloginPassword, String appId, String oneloginDomain, Map<String, String> mfaVerifyInfo)
			throws Exception {
		return getSamlResponse(olClient, scanner, oneloginUsernameOrEmail, oneloginPassword, appId,
				oneloginDomain, mfaVerifyInfo, null);
	}

	public static Boolean checkDeviceExists(List<Device> devices, Long deviceId) {
		for (Device device : devices) {
			if (device.getID() == deviceId) {
				return true;
			}
		}
		return false;
	}
	
	public static Map<String, Object> verifyToken(Client olClient, Scanner scanner, String appId,
			String deviceIdStr, String stateToken, String otpToken, Map<String, String> mfaVerifyInfo) {
		Map<String, Object> result = new HashMap<String, Object>();
		try {
			SAMLEndpointResponse samlEndpointResponseAfterVerify = olClient.getSAMLAssertionVerifying(appId,
				deviceIdStr, stateToken, otpToken, null);
			mfaVerifyInfo.put("otpToken", otpToken);
			String samlResponse = samlEndpointResponseAfterVerify.getSAMLResponse();	
			result.put("samlResponse", samlResponse);
			result.put("mfaVerifyInfo", mfaVerifyInfo);
		} catch (Exception OAuthProblemException){
			System.out.print("The OTP Token was invalid, please introduce a new one: ");
			otpToken = scanner.next();
			result = verifyToken(olClient, scanner, appId,
					deviceIdStr, stateToken, otpToken, mfaVerifyInfo);		
		}
		return result;
	}

}
