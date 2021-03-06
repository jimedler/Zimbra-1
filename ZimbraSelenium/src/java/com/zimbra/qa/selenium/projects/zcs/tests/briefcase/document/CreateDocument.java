package com.zimbra.qa.selenium.projects.zcs.tests.briefcase.document;

import java.lang.reflect.Method;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.zimbra.qa.selenium.framework.core.*;
import com.zimbra.qa.selenium.framework.util.HarnessException;
import com.zimbra.qa.selenium.framework.util.RetryFailedTests;
import com.zimbra.qa.selenium.projects.zcs.tests.CommonTest;


/**
 * @author Jitesh Sojitra
 * 
 */
public class CreateDocument extends CommonTest {
	//--------------------------------------------------------------------------
	// SECTION 1: DATA-PROVIDERS
	//--------------------------------------------------------------------------
	@DataProvider(name = "briefcaseDataProvider")
	public Object[][] createData(Method method) {
		String test = method.getName();
		if (test.equals("test1")) {
			return new Object[][] { { getLocalizedData_NoSpecialChar() } };
		} else {
			return new Object[][] { { "" } };
		}
	}

	// --------------
	// section 2 BeforeClass
	// --------------
	@BeforeClass(groups = { "always" })
	public void zLogin() throws Exception {
		super.NAVIGATION_TAB="briefcase";
		super.zLogin();
	}

	@Test(
			dataProvider = "briefcaseDataProvider", 
			groups = { "sanity", "smoke", "full" }, 
			retryAnalyzer = RetryFailedTests.class)
	public void test1(String briefcaseName) throws Exception {
		if (SelNGBase.isExecutionARetry.get())
			handleRetry();

		// dummy test

		SelNGBase.needReset.set(false);
		
		throw new HarnessException("implement me!");
	}
}