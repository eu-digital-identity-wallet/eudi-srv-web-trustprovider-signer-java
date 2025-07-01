/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.rssp.security.openid4vp;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@SpringBootTest
@RunWith(SpringJUnit4ClassRunner.class)
public class VerifierClientTest {

    public static String Authentication = "Authentication";
    public static String Authorization = "Authorization";

    @Test
    public void testSingleThreadAddVerifierVariables() throws Exception {
        // Arrange
        VerifierCreatedVariables verifierVariables = new VerifierCreatedVariables();
        int len = verifierVariables.getAllVariables().size(); // original size

        // Act
        SecureRandom prng = new SecureRandom();
        String randomNum = String.valueOf(prng.nextInt());
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] result = sha.digest(randomNum.getBytes());
        String nonce = Base64.getUrlEncoder().encodeToString(result);
        String user = "test";
        String presentation_id = "presentation_id";
        verifierVariables.addUsersVerifierCreatedVariable(user, "same", Authorization, nonce, presentation_id);

        // Assert
        Map<String, VerifierCreatedVariable> variables = verifierVariables.getAllVariables();
        int len1 = variables.size();
        Assert.assertEquals(len1, len + 1);

        boolean found = variables.containsKey(user);
		Assert.assertTrue(found);

        VerifierCreatedVariable vcv = variables.get(user);
        Assert.assertEquals(nonce, vcv.getNonce());
        Assert.assertEquals(presentation_id, vcv.getPresentation_id());
        Assert.assertEquals(Authorization, vcv.getType());
    }

    @Test
    public void testSingleThreadContainsVerifierVariables() throws Exception {
        // Arrange
        VerifierCreatedVariables verifierVariables = new VerifierCreatedVariables();

        // Act
        SecureRandom prng = new SecureRandom();
        String randomNum = String.valueOf(prng.nextInt());
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] result = sha.digest(randomNum.getBytes());
        String nonce = Base64.getUrlEncoder().encodeToString(result);
        String user = "test";
        String presentation_id = "presentation_id";
        verifierVariables.addUsersVerifierCreatedVariable(user, "same", Authorization, nonce, presentation_id);

        // Assert
        Map<String, VerifierCreatedVariable> variables = verifierVariables.getAllVariables();
        boolean found = variables.containsKey(user);
		Assert.assertTrue(found);

        boolean found2 = verifierVariables.containsUser(user);
		Assert.assertTrue(found2);
    }

    @Test
    public void testSingleThreadGetAndRemoveVerifierVariables() throws Exception {
        // Arrange
        VerifierCreatedVariables verifierVariables = new VerifierCreatedVariables();
        int len = verifierVariables.getAllVariables().size(); // original size

        // Act
        SecureRandom prng = new SecureRandom();
        String randomNum = String.valueOf(prng.nextInt());
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] result = sha.digest(randomNum.getBytes());
        String nonce = Base64.getUrlEncoder().encodeToString(result);
        String user = "test";
        String presentation_id = "presentation_id";
        verifierVariables.addUsersVerifierCreatedVariable(user, "same", Authorization, nonce, presentation_id);

        // Assert
        Map<String, VerifierCreatedVariable> variables = verifierVariables.getAllVariables();
        int len1 = variables.size();
        Assert.assertEquals(len1, len + 1);

        boolean found = variables.containsKey(user);
		Assert.assertTrue(found);

        VerifierCreatedVariable vcv = variables.get(user);
        Assert.assertNotNull(vcv);

        VerifierCreatedVariable vcvGet = verifierVariables.getUsersVerifierCreatedVariable(user, "same", Authorization);
        Assert.assertNotNull(vcvGet);

        Assert.assertEquals(nonce, vcvGet.getNonce());
        Assert.assertEquals(vcv, vcvGet);

        int lenOG = verifierVariables.getAllVariables().size();
        Assert.assertEquals(len, lenOG);

        Map<String, VerifierCreatedVariable> variablesAfterRemove = verifierVariables.getAllVariables();
        boolean notFound = variablesAfterRemove.containsKey(user);
		Assert.assertFalse(notFound);
    }

    @Test
    public void testSingleThreadAccessToVerifierCreatedVariables() throws Exception {
        VerifierCreatedVariables verifierVariables = new VerifierCreatedVariables();

        int len = verifierVariables.getAllVariables().size();

        SecureRandom prng = new SecureRandom();
        String randomNum = String.valueOf(prng.nextInt());
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] result = sha.digest(randomNum.getBytes());
        String nonce = Base64.getUrlEncoder().encodeToString(result);
        String user = "test";
        String presentation_id = "presentation_id";

        verifierVariables.addUsersVerifierCreatedVariable(user, "same", Authorization, nonce, presentation_id);

        // assert len1 == len + 1;
        int len1 = verifierVariables.getAllVariables().size();
        Assert.assertEquals(len1, len + 1);

        // assert containsUser() == true;
        boolean found = verifierVariables.containsUser(user);
		Assert.assertTrue(found);

        VerifierCreatedVariable vcv = verifierVariables.getUsersVerifierCreatedVariable(user, "same", Authorization);
        Assert.assertEquals(nonce, vcv.getNonce());

        found = verifierVariables.containsUser(user);
		Assert.assertFalse(found);
    }

    @Test
    public void testMultiThreadAddVerifierVariables() throws Exception {
        // Arrange
        int numberOfThreads = 10;
        ExecutorService service = Executors.newFixedThreadPool(numberOfThreads);
        CountDownLatch latch = new CountDownLatch(numberOfThreads);

        VerifierCreatedVariables verifierVariables = new VerifierCreatedVariables();
        int len = verifierVariables.getAllVariables().size(); // original size

        // Act
        for (int i = 0; i < numberOfThreads; i++) {
            final int index = i;
            service.submit(() -> {
                try {
                    SecureRandom prng = new SecureRandom();
                    String randomNum = String.valueOf(prng.nextInt());
                    MessageDigest sha = MessageDigest.getInstance("SHA-256");
                    byte[] result = sha.digest(randomNum.getBytes());
                    String nonce = Base64.getUrlEncoder().encodeToString(result);
                    String user = "test" + Integer.toString(index);
                    String presentation_id = "presentation_id" + index;

                    verifierVariables.addUsersVerifierCreatedVariable(user, "same", Authorization, nonce, presentation_id);

                    // Assert
                    Map<String, VerifierCreatedVariable> variables = verifierVariables.getAllVariables();
                    boolean found = variables.containsKey(user);
					Assert.assertTrue(found);

                    VerifierCreatedVariable vcv = variables.get(user);
                    Assert.assertEquals(nonce, vcv.getNonce());
                    Assert.assertEquals(presentation_id, vcv.getPresentation_id());
                    Assert.assertEquals(Authorization, vcv.getType());
                } catch (Exception e) {
                    e.printStackTrace();
                }
                latch.countDown();
            });
        }
        latch.await();

        // Assert
        Map<String, VerifierCreatedVariable> variables = verifierVariables.getAllVariables();
        int len1 = variables.size();
        Assert.assertEquals(len1, len + numberOfThreads);

        Set<String> keys = variables.keySet();
        for (int i = 0; i < numberOfThreads; i++) {
            String user = "test" + i;
            keys.contains(user);
        }

    }

    @Test
    public void testMultiThreadContainsVerifierVariables() throws Exception {

        // Arrange
        int numberOfThreads = 10;
        ExecutorService service = Executors.newFixedThreadPool(numberOfThreads);
        CountDownLatch latch = new CountDownLatch(numberOfThreads);

        VerifierCreatedVariables verifierVariables = new VerifierCreatedVariables();
        int len = verifierVariables.getAllVariables().size(); // original size

        // Act
        for (int i = 0; i < numberOfThreads; i++) {
            final int index = i;
            service.submit(() -> {
                try {
                    SecureRandom prng = new SecureRandom();
                    String randomNum = String.valueOf(prng.nextInt());
                    MessageDigest sha = MessageDigest.getInstance("SHA-256");
                    byte[] result = sha.digest(randomNum.getBytes());
                    String nonce = Base64.getUrlEncoder().encodeToString(result);
                    String user = "test" + Integer.toString(index);
                    String presentation_id = "presentation_id" + index;

                    verifierVariables.addUsersVerifierCreatedVariable(user, "same", Authorization, nonce, presentation_id);

                    // Assert
                    Map<String, VerifierCreatedVariable> variables = verifierVariables.getAllVariables();
                    boolean found = variables.containsKey(user);
					Assert.assertTrue(found);

                    boolean found2 = verifierVariables.containsUser(user);
					Assert.assertTrue(found2);

                    Assert.assertEquals(found, found2);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                latch.countDown();
            });
        }
        latch.await();

        // Assert
        Map<String, VerifierCreatedVariable> variables = verifierVariables.getAllVariables();
        int len1 = variables.size();
        Assert.assertEquals(len + numberOfThreads, len1);
    }

    @Test
    public void testMultiThreadGetAndRemoveVerifierVariables() throws Exception {

        // Arrange
        int numberOfThreads = 10;
        ExecutorService service = Executors.newFixedThreadPool(numberOfThreads);
        CountDownLatch latch = new CountDownLatch(numberOfThreads);

        VerifierCreatedVariables verifierVariables = new VerifierCreatedVariables();
        int len = verifierVariables.getAllVariables().size(); // original size

        // Act
        for (int i = 0; i < numberOfThreads; i++) {
            final int index = i;
            service.submit(() -> {
                try {
                    SecureRandom prng = new SecureRandom();
                    String randomNum = String.valueOf(prng.nextInt());
                    MessageDigest sha = MessageDigest.getInstance("SHA-256");
                    byte[] result = sha.digest(randomNum.getBytes());
                    String nonce = Base64.getUrlEncoder().encodeToString(result);
                    String user = "test" + Integer.toString(index);
                    String presentation_id = "presentation_id" + index;

                    verifierVariables.addUsersVerifierCreatedVariable(user, "same", Authorization, nonce, presentation_id);

                    // Assert
                    Map<String, VerifierCreatedVariable> variables = verifierVariables.getAllVariables();
                    boolean found = variables.containsKey(user);
					Assert.assertTrue(found);

                    VerifierCreatedVariable vcv = variables.get(user);
                    Assert.assertNotNull(vcv);
                    Assert.assertEquals(nonce, vcv.getNonce());

                    // wait(1000);

                    VerifierCreatedVariable vcvGet = verifierVariables.getUsersVerifierCreatedVariable(user, "same",
                            Authorization);
                    Assert.assertNotNull(vcvGet);
                    Assert.assertEquals(vcv, vcvGet);

                    Map<String, VerifierCreatedVariable> variablesAfterRemove = verifierVariables.getAllVariables();
                    boolean notFound = variablesAfterRemove.containsKey(user);
					Assert.assertFalse(notFound);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                latch.countDown();
            });
        }

        latch.await();
        service.shutdown();

        // Assert
        Assert.assertEquals(len, verifierVariables.getAllVariables().size());
    }

    @Test
    public void multiThreadAccessToVerifierCreatedVariables() throws InterruptedException {
        int numberOfThreads = 10;
        ExecutorService service = Executors.newFixedThreadPool(numberOfThreads);
        CountDownLatch latch = new CountDownLatch(numberOfThreads);

        VerifierCreatedVariables verifierVariables = new VerifierCreatedVariables();

        for (int i = 0; i < numberOfThreads; i++) {
            final int index = i;
            service.submit(() -> {
                try {
                    SecureRandom prng = new SecureRandom();
                    String randomNum = String.valueOf(prng.nextInt());
                    MessageDigest sha = MessageDigest.getInstance("SHA-256");
                    byte[] result = sha.digest(randomNum.getBytes());
                    String nonce = Base64.getUrlEncoder().encodeToString(result);
                    String user = "test" + Integer.toString(index);
                    String presentation_id = "presentation_id" + index;

                    verifierVariables.addUsersVerifierCreatedVariable(user, "same", Authorization, nonce, presentation_id);

                    // assert containsUser() == true;
                    boolean found = verifierVariables.containsUser(user);
					Assert.assertTrue(found);

                    VerifierCreatedVariable vcv = verifierVariables.getUsersVerifierCreatedVariable(user, "same", Authorization);
                    Assert.assertEquals(nonce, vcv.getNonce());

                    found = verifierVariables.containsUser(user);
					Assert.assertFalse(found);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                latch.countDown();
            });
        }
        latch.await();

        Assert.assertEquals(0, verifierVariables.getAllVariables().size());
    }

}
