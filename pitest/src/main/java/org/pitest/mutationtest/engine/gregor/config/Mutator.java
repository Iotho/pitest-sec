/*
 * Copyright 2010 Henry Coles
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 */
package org.pitest.mutationtest.engine.gregor.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;

import org.pitest.functional.FCollection;
import org.pitest.functional.prelude.Prelude;
import org.pitest.help.Help;
import org.pitest.help.PitHelpError;
import org.pitest.mutationtest.engine.gregor.MethodMutatorFactory;
import org.pitest.mutationtest.engine.gregor.mutators.ArgumentPropagationMutator;
import org.pitest.mutationtest.engine.gregor.mutators.BooleanFalseReturnValsMutator;
import org.pitest.mutationtest.engine.gregor.mutators.BooleanTrueReturnValsMutator;
import org.pitest.mutationtest.engine.gregor.mutators.ConditionalsBoundaryMutator;
import org.pitest.mutationtest.engine.gregor.mutators.ConstructorCallMutator;
import org.pitest.mutationtest.engine.gregor.mutators.EmptyObjectReturnValsMutator;
import org.pitest.mutationtest.engine.gregor.mutators.IncrementsMutator;
import org.pitest.mutationtest.engine.gregor.mutators.InlineConstantMutator;
import org.pitest.mutationtest.engine.gregor.mutators.InvertNegsMutator;
import org.pitest.mutationtest.engine.gregor.mutators.MathMutator;
import org.pitest.mutationtest.engine.gregor.mutators.NegateConditionalsMutator;
import org.pitest.mutationtest.engine.gregor.mutators.NonVoidMethodCallMutator;
import org.pitest.mutationtest.engine.gregor.mutators.NullReturnValsMutator;
import org.pitest.mutationtest.engine.gregor.mutators.PrimitiveReturnsMutator;
import org.pitest.mutationtest.engine.gregor.mutators.RemoveConditionalMutator;
import org.pitest.mutationtest.engine.gregor.mutators.RemoveConditionalMutator.Choice;
import org.pitest.mutationtest.engine.gregor.mutators.ReturnValsMutator;
import org.pitest.mutationtest.engine.gregor.mutators.VoidMethodCallMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.NakedReceiverMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.RemoveIncrementsMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.RemoveSwitchMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.SwitchMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.CookieHttpOnlyFlagDisableMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.CookieSecureFlagDisableMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.DisableDOCTYPEVerificationOnXMLParserWithSAXMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.DisableDOCTYPEVerificationOnXMLParserWithXMLReaderMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.DisableDOSVerificationOnXMLParserWithSAXMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.DisableDOSVerificationOnXMLParserWithXMLReaderMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.HostNameVerifyToTrueMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.PatternMatchesAnythingMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.RSAWithShortKeyMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.RemoveSSLInSocketMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.SQLInjectionOKWithJDBCMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.StringMatcherMatchesAnythingMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.TrustUserInputInFilesRetrievementMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.UseBLOWFISHWithShortKeyMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.UseECBInSymmetricEncryptionMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.UseMD5ForEncryptionJAVAStandardMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.UseMD5ForEncryptionWithBouncyCastleMutator;
import org.pitest.mutationtest.engine.gregor.mutators.experimental.security.UseWeakPseudoRandomNumberGeneratorMutator;

public final class Mutator {

  private static final Map<String, Iterable<MethodMutatorFactory>> MUTATORS = new LinkedHashMap<>();

  static {

    /**
     * Default mutator that inverts the negation of integer and floating point
     * numbers.
     */
    add("INVERT_NEGS", InvertNegsMutator.INVERT_NEGS_MUTATOR);

    /**
     * Default mutator that mutates the return values of methods.
     */
    add("RETURN_VALS", ReturnValsMutator.RETURN_VALS_MUTATOR);

    /**
     * Optional mutator that mutates integer and floating point inline
     * constants.
     */
    add("INLINE_CONSTS", new InlineConstantMutator());

    /**
     * Default mutator that mutates binary arithmetic operations.
     */
    add("MATH", MathMutator.MATH_MUTATOR);

    /**
     * Default mutator that removes method calls to void methods.
     *
     */
    add("VOID_METHOD_CALLS", VoidMethodCallMutator.VOID_METHOD_CALL_MUTATOR);

    /**
     * Default mutator that negates conditionals.
     */
    add("NEGATE_CONDITIONALS",
        NegateConditionalsMutator.NEGATE_CONDITIONALS_MUTATOR);

    /**
     * Default mutator that replaces the relational operators with their
     * boundary counterpart.
     */
    add("CONDITIONALS_BOUNDARY",
        ConditionalsBoundaryMutator.CONDITIONALS_BOUNDARY_MUTATOR);

    /**
     * Default mutator that mutates increments, decrements and assignment
     * increments and decrements of local variables.
     */
    add("INCREMENTS", IncrementsMutator.INCREMENTS_MUTATOR);

    /**
     * Optional mutator that removes local variable increments.
     */

    add("REMOVE_INCREMENTS", RemoveIncrementsMutator.REMOVE_INCREMENTS_MUTATOR);

    /**
     * Optional mutator that removes method calls to non void methods.
     */
    add("NON_VOID_METHOD_CALLS",
        NonVoidMethodCallMutator.NON_VOID_METHOD_CALL_MUTATOR);

    /**
     * Optional mutator that replaces constructor calls with null values.
     */
    add("CONSTRUCTOR_CALLS", ConstructorCallMutator.CONSTRUCTOR_CALL_MUTATOR);

    /**
     * Removes conditional statements so that guarded statements always execute
     * The EQUAL version ignores LT,LE,GT,GE, which is the default behaviour,
     * ORDER version mutates only those.
     */

    add("REMOVE_CONDITIONALS_EQ_IF", new RemoveConditionalMutator(Choice.EQUAL,
        true));
    add("REMOVE_CONDITIONALS_EQ_ELSE", new RemoveConditionalMutator(
        Choice.EQUAL, false));
    add("REMOVE_CONDITIONALS_ORD_IF", new RemoveConditionalMutator(
        Choice.ORDER, true));
    add("REMOVE_CONDITIONALS_ORD_ELSE", new RemoveConditionalMutator(
        Choice.ORDER, false));
    addGroup("REMOVE_CONDITIONALS", RemoveConditionalMutator.makeMutators());

    add("TRUE_RETURNS", BooleanTrueReturnValsMutator.BOOLEAN_TRUE_RETURN);
    add("FALSE_RETURNS", BooleanFalseReturnValsMutator.BOOLEAN_FALSE_RETURN);
    add("PRIMITIVE_RETURNS", PrimitiveReturnsMutator.PRIMITIVE_RETURN_VALS_MUTATOR);
    add("EMPTY_RETURNS", EmptyObjectReturnValsMutator.EMPTY_RETURN_VALUES);
    add("NULL_RETURNS", NullReturnValsMutator.NULL_RETURN_VALUES);
    addGroup("RETURNS", betterReturns());

    /**
     * Experimental mutator that removed assignments to member variables.
     */
    add("EXPERIMENTAL_MEMBER_VARIABLE",
        new org.pitest.mutationtest.engine.gregor.mutators.experimental.MemberVariableMutator());

    /**
     * Experimental mutator that swaps labels in switch statements
     */
    add("EXPERIMENTAL_SWITCH",
        new org.pitest.mutationtest.engine.gregor.mutators.experimental.SwitchMutator());

    /**
     * Experimental mutator that replaces method call with one of its parameters
     * of matching type
     */
    add("EXPERIMENTAL_ARGUMENT_PROPAGATION",
        ArgumentPropagationMutator.ARGUMENT_PROPAGATION_MUTATOR);

    /**
     * Experimental mutator that replaces method call with this
     */
    add("EXPERIMENTAL_NAKED_RECEIVER", NakedReceiverMutator.NAKED_RECEIVER);


    /**
     * 1 From : http://find-sec-bugs.github.io/bugs.htm#PREDICTABLE_RANDOM
     * Mutator that replaces any call to SecureRandom.nextBytes to (new
     * Random).nextBytes. The use of Random instead of SecureRandom leads to
     * use a predictable pseudorandom number generator. This mutation
     * operator can lead to weaknesses in secure communications or simply
     * encryption, it facilitates the work of the attacker.
     */
    add("USE_PSEUDO_RANDOM_MUTATOR",
        UseWeakPseudoRandomNumberGeneratorMutator.USE_WEAK_PSEUDO_RANDOM_NUMBER_GENERATOR_MUTATOR);

    /**
     * 2 From : http://find-sec-bugs.github.io/bugs.htm#PATH_TRAVERSAL_IN
     * Mutator that removes any call to the user-input-sanitization method
     * FilenameUtils.getName(name).
     *
     * Example: if name = "a/b/c.txt", getName will give "c.txt".
     *
     * The sanitization method prevents the attacker to access to the
     * folders under the one you give him access to.
     *
     * This mutation operator can lead to path traversal vulnerabilities.
     */
    add("TRUST_USER_INPUT_IN_FILES_RETRIEVEMENT",
        TrustUserInputInFilesRetrievementMutator.TRUST_USER_INPUT_IN_FILES_RETRIEVEMENT);

    /**
     * 3 From :
     * http://find-sec-bugs.github.io/bugs.htm#WEAK_MESSAGE_DIGEST_MD5
     * Mutator that changes X-Digest's where X can be SHA-256 or another
     * algorithm of hashing to MD5Digest in a pattern of encryption given by
     * http://find-sec-bugs.github.io/bugs.htm#WEAK_MESSAGE_DIGEST_MD5. This
     * mutator can lead to weakness in hashing because of collision in MD5
     * hashing function.
     */
    add("USE_MD5_FOR_ENCRYPTION_WITH_BOUNCY_CASTLE",
        UseMD5ForEncryptionWithBouncyCastleMutator.USE_MD5_FOR_ENCRYPTION_WITH_BOUNCY_CASTLE);

    /**
     * 4 From :
     * http://find-sec-bugs.github.io/bugs.htm#WEAK_MESSAGE_DIGEST_MD5
     * Mutator that replaces any call to new Digest("X") constructor by new
     * Digest("MD5"). This mutator can lead to weaknesses in hashing because
     * of collision in MD5 hashing function.
     */
    add("USE_MD5_FOR_ENCRYPTION_JAVA_STANDARD_MUTATOR",
        UseMD5ForEncryptionJAVAStandardMutator.USE_MD5_FOR_ENCRYPTION_JAVA_STANDARD_MUTATOR);

    /**
     * 5 From :
     * http://find-sec-bugs.github.io/bugs.htm#WEAK_HOSTNAME_VERIFIER
     * Mutator that replaces any call to (boolean)
     * HostnameVerifier.verify(hostname,session) by "true".
     *
     * HostNameVerifier.verify is a standard way to
     * "Verify that the host name is an acceptable match with the server's authentication scheme."
     * ref: HostNameVerifier doc
     *
     * Usually, the HostNameVerifier.verify implementation (HostNameVerifier
     * is an interface) verifies the Certificate of the host before
     * returning true or false.
     *
     * This mutator can lead to vulnerabilities in the authentication
     * process of the program since it accepts anyone.
     */
    add("HOST_NAME_VERIFY_TO_TRUE",
        HostNameVerifyToTrueMutator.HOST_NAME_VERIFY_TO_TRUE);

    /**
     * 6 From : http://find-sec-bugs.github.io/bugs.htm#XXE_SAXPARSER
     * Mutator that adds
     * saxParserFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,
     * false); before any call of saxParserFactory.newSAXParser(); The
     * SAXParser is an XMLParser object. The call to
     * saxParserFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,
     * false) will disable the checking for DOS attacks before parsing. This
     * mutator will make any SAXParser created by the saxParserFactory
     * vulnerable to DOS attacks.
     */
    add("XML_PARSER_VULNERABLE_TO_DOS_WITH_SAX",
        DisableDOSVerificationOnXMLParserWithSAXMutator.XML_PARSER_VULNERABLE_TO_DOS_WITH_SAX);

    /**
     * 7 From : http://find-sec-bugs.github.io/bugs.htm#XXE_XMLREADER.
     * Mutator that adds
     * xmlReader.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false);
     * before any call of xmlReader.parse(InputSource) The XMLReader is an
     * XMLParser object. The call to
     * xmlReader.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false)
     * will disable the checking for DOS attacks before parsing. This
     * mutator will make the XMLReader vulnerable to DOS attacks.
     */
    add("XML_PARSER_VULNERABLE_TO_DOS_WITH_XMLREADER",
        DisableDOSVerificationOnXMLParserWithXMLReaderMutator.XML_PARSER_VULNERABLE_TO_DOS_WITH_XMLREADER);

    /**
     * 8 From : http://find-sec-bugs.github.io/bugs.htm#XXE_SAXPARSER
     * Mutator that adds saxParserFactory.setFeature(
     * "http://apache.org/xml/features/disallow-doctype-decl", false);
     * before any call of saxParserFactory.newSAXParser(); The SAXParser is
     * an XMLParser object. This mutator will make any SAXParser created by
     * saxParserFactory vulnerable to XXE attacks if it parses input from an
     * external source.
     */
    add("XML_PARSER_VULNERABLE_TO_DOCTYPE_WITH_SAX",
        DisableDOCTYPEVerificationOnXMLParserWithSAXMutator.XML_PARSER_VULNERABLE_TO_XXE_WITH_SAX);

    /**
     * 9 From : http://find-sec-bugs.github.io/bugs.htm#XXE_XMLREADER
     * Mutator that adds XMLReader.setFeature(
     * "http://apache.org/xml/features/disallow-doctype-decl", false);
     * before any call of XMLReader.parse(InputSource); This mutator will
     * make the XMLReader vulnerable to XXE attacks if it parses input from
     * an external source.
     */
    add("XML_PARSER_VULNERABLE_TO_DOCTYPE_WITH_XMLREADER",
        DisableDOCTYPEVerificationOnXMLParserWithXMLReaderMutator.XML_PARSER_VULNERABLE_TO_XXE_WITH_XMLREADER);

    /**
     * 10 From : http://find-sec-bugs.github.io/bugs.htm#UNENCRYPTED_SOCKET
     * Mutator that replaces any (Socket)
     * SSLSocketFactory.getDefault().createSocket("address", portNumber); to
     * (Socket) SocketFactory.getDefault().createSocket("address", 80); This
     * mutator will create a Socket that uses HTTP instead of HTTPS. It can
     * lead to un-encrypted communications that can be read by an attacker
     * intercepting the network traffic.
     */
    add("REMOVE_SECURE_SOCKET_MUTATOR",
        RemoveSSLInSocketMutator.REMOVE_SECURE_SOCKET_MUTATOR);

    /**
     * 11 From : http://find-sec-bugs.github.io/bugs.htm#INSECURE_COOKIE
     * Mutator that removes any call to cookie.setSecure(true)
     * cookie.setSecure(true) adds a flag to the cookie sent by the server
     * telling the browser to never send this cookie in insecure context.
     * This mutation operator can enable attackers to read private
     * information stocked in cookies if they intercept the communication.
     */
    add("REMOVE_SECURE_FLAG_MUTATOR",
        CookieSecureFlagDisableMutator.REMOVE_SECURE_FLAG_MUTATOR);

    /**
     * 12 From : http://find-sec-bugs.github.io/bugs.htm#HTTPONLY_COOKIE
     * Mutator that removes any cookie.setHttpOnly(true);
     * cookie.setHttpOnly(true) adds a flag to the cookie sent by the server
     * telling the browser to make sure that the cookie can not be red by
     * malicious script. This mutation operator can lead to weaknesses like
     * session hijacking using cross-site scripting.
     */
    add("REMOVE_HTTPONLY_FLAG_MUTATOR",
        CookieHttpOnlyFlagDisableMutator.REMOVE_HTTPONLY_FLAG_MUTATOR);

    /**
     * 13 From : http://find-sec-bugs.github.io/bugs.htm#RSA_KEY_SIZE
     * Mutator that makes the program use a small key for RSA encryption
     * (512bits) where it used a secured-size key (>=2048bits).
     *
     * It replaces any call to keyPairGenerator.initialize(X); where X>=2048
     * by keyPairGenerator.initialize(512)
     *
     * The only way to know that the KeyPairGenerator is for RSA-use is to
     * have the creation of the KeyPairGenerator in the same method as the
     * initialization. So,the mutation operator is applied only if we can
     * find keyPairGenerator = KeyPairGenerator.getInstance("RSA") in the
     * same method as the initialization.
     *
     * This mutation operator can lead to weaknesses in secure
     * communications using RSA, it facilitates the brute force attack for
     * instance.
     */
    add("RSA_WITH_SHORT_KEY_MUTATOR",
        RSAWithShortKeyMutator.RSA_WITH_SHORT_KEY_MUTATOR);

    /**
     * 14 From : http://find-sec-bugs.github.io/bugs.htm#BLOWFISH_KEY_SIZE
     * Mutator that makes the program use a small key for BLOWFISH
     * encryption (64bits) where it used a secured-size key (>=2048bits).
     *
     * It replaces any KeyGenerator.init(X); where X>=128 to
     * KeyGenerator.init(64)
     *
     * The only way to know that the KeyGenerator is for BLOWFISH-use is to
     * have the creation of the KeyGenerator in the same method as the
     * initialization. So,the mutation operator is applied only if we can
     * find keyGenerator = KeyGenerator.getInstance("BLOWFISH") in the same
     * method as the initialization.
     *
     * This mutation operator can lead to weaknesses in secure encryption
     * using BLOWFISH, it facilitates a brute force attack for instance.
     */
    add("USE_BLOWFISH_WITH_SHORT_KEY",
        UseBLOWFISHWithShortKeyMutator.USE_BLOWFISH_WITH_SHORT_KEY);

    /**
     * 15 From : http://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_JDBC
     * Mutator that replaces the initialization and the execution of a
     * PreparedStatement by the initialization and execution of a Statement,
     * enabling SQL injection.
     *
     * For the mutator to be applied, the following pattern must be found in
     * one method:
     *
     * PreparedStatement preparedStatement =
     * connection.prepareStatement("querryContainingOneOrSeveral'?'");
     * preparedStatement.setX0(1, value); preparedStatement.setXn(1, value);
     * where Xi are in {Float, Double, Boolean, Long, String, Int}
     * preparedStatement.execute() or executeQuerry() or executeUpdate();
     *
     * The mutator will only change the last line of the pattern to
     * connection.createStatement().execute(
     * "querry where '?' are replaced by the values set before")
     *
     * Example: PreparedStatement updateSales = conn.prepareStatement(
     * "update COFFEES set SALES = ? where COF_NAME = ?");
     * updateSales.setInt(1, nbSales) updateSales.setString(2, coffeeName);
     * updateSales.execute();
     *
     * will be mutated to
     *
     * PreparedStatement updateSales = conn.prepareStatement(
     * "update COFFEES set SALES = ? where COF_NAME = ?");
     * updateSales.setInt(1, nbSales); updateSales.setString(2, coffeeName);
     * conn.createStatement().execute("update COFFEES set SALES = '"
     * +nbSales+"' where COF_NAME = '"+coffeeName+"'");
     *
     * This mutation operator can lead to SQL injection because the
     * preparedStatement.setX methods sanitize the inputs. For instance, if
     * the coffeeName can be controlled by an attacker, he must just insert
     * coffeeName = "randomName' or 'a'='a";
     */
    add("SQL_INJECTION_OK_WITH_JDBC",
        SQLInjectionOKWithJDBCMutator.SQL_INJECTION_OK_WITH_JDBC);

    /**
     * 16 From : http://find-sec-bugs.github.io/bugs.htm#DES_USAGE Mutator
     * that replaces the creation and initialization of a secure symmetric
     * Cipher (not DES) to the creation and initialization of a DES cipher.
     * For the mutator to be applied, the following pattern must be found in
     * one method:
     *
     * Cipher c = Cipher.getInstance("SECUREALGORITHM/MODE/PADDING");
     * c.init(Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE, key);
     *
     * The mutator will change both lines with:
     *
     * Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
     * c.init(Cipher.ENCRYPT_MODE,new
     * SecretKeySpec(key.getEncoded(),0,8,"DES"));
     *
     * Because DES is known to be insecure, this mutation operator can lead
     * to weaknesses in symmetric encryption.
     */
    // add(USE_DES_FOR_SYMMETRIC_ENCRYPTION",NEWUseDESForSymmetricEncryptionMutator.USE_DES_FOR_SYMMETRIC_ENCRYPTION);

    /**
     * 17 From : http://find-sec-bugs.github.io/bugs.htm#ECB_MODE Mutator
     * that replaces any Cipher.getInstance("X/Y/Z"); where Y != ECB by
     * Cipher.getInstance("X/ECB/Z"); If Y and Z are null, replaces it by
     * Cipher.getInstance("X/ECB/PKCS5Padding)
     *
     * The ECB mode means that if two plaintext blocks are identical, the
     * cipherText blocks obtained will also be identical.
     *
     * This mutation operator can lead to weaknesses in encryption, it
     * facilitates the decryption of a cipherText by an attacker.
     */
    add("USE_ECB_IN_SYMMETRIC_ENCRYPTION",
        UseECBInSymmetricEncryptionMutator.USE_ECB_IN_SYMMETRIC_ENCRYPTION);

    // 18 XXXX DOESNT WORK XXXX
    // add("MUTATE_TRUSTMANAGER_TO_USELESS",NEWUselessX509TrustManagerMutator.MUTATE_TRUSTMANAGER_TO_USELESS);

    /**
     * 19 From : http://askMike.hisIdea.gr Mutator that replaces any
     * Pattern.compile(goodRegex); by Pattern.compile("([^¤]*)"); The regex
     * ([^¤]*) says: accept a String containing anything but ¤, it can be as
     * long as you want. If ¤ is never used in inputs, the mutation operator
     * is giving you a regex that lets anything pass.
     *
     * This mutation operator can suppress sanitization of inputs using
     * Regex's and facilitate an attack.
     *
     */
    add("PATTERN_MATCHES_ANYTHING_MUTATOR",
        PatternMatchesAnythingMutator.PATTERN_MATCHES_ANYTHING_MUTATOR);




    /**
     * 20 From : http://askMike.hisIdea.gr Mutator that replaces any call to
     * stringpattern.matches(goodRegex); by
     * stringpattern.matches("([^¤]*)"); The regex ([^¤]*) says: accept a
     * String containing anything but ¤, it can be as long as you want. If ¤
     * is never used in inputs, the mutation operator is giving you a regex
     * that lets anything pass.
     *
     * This mutation operator can suppress sanitization of inputs and
     * facilitate an attack.
     *
     */
    add("STRING_MATCHER_MATCHES_ANYTHING_MUTATOR",
        StringMatcherMatchesAnythingMutator.STRING_MATCHER_MATCHES_ANYTHING_MUTATOR);

    addGroup("REMOVE_SWITCH", RemoveSwitchMutator.makeMutators());
    addGroup("DEFAULTS", defaults());
    addGroup("STRONGER", stronger());
    addGroup("SECURITY", security());
    addGroup("ALL", all());
  }

  public static Collection<MethodMutatorFactory> all() {
    return fromStrings(MUTATORS.keySet());
  }

  private static Collection<MethodMutatorFactory> stronger() {
    return combine(
        defaults(),
        group(new RemoveConditionalMutator(Choice.EQUAL, false),
            new SwitchMutator()));
  }

  private static Collection<MethodMutatorFactory> combine(
      Collection<MethodMutatorFactory> a, Collection<MethodMutatorFactory> b) {
    final List<MethodMutatorFactory> l = new ArrayList<>(a);
    l.addAll(b);
    return l;
  }

  /**
   * Default set of mutators - designed to provide balance between strength and
   * performance
   */
  public static Collection<MethodMutatorFactory> defaults() {
    return group(InvertNegsMutator.INVERT_NEGS_MUTATOR,
        ReturnValsMutator.RETURN_VALS_MUTATOR, MathMutator.MATH_MUTATOR,
        VoidMethodCallMutator.VOID_METHOD_CALL_MUTATOR,
        NegateConditionalsMutator.NEGATE_CONDITIONALS_MUTATOR,
        ConditionalsBoundaryMutator.CONDITIONALS_BOUNDARY_MUTATOR,
        IncrementsMutator.INCREMENTS_MUTATOR);
  }

  public static Collection<MethodMutatorFactory> security() {
    return group(
        UseWeakPseudoRandomNumberGeneratorMutator.USE_WEAK_PSEUDO_RANDOM_NUMBER_GENERATOR_MUTATOR,
        TrustUserInputInFilesRetrievementMutator.TRUST_USER_INPUT_IN_FILES_RETRIEVEMENT,
        UseMD5ForEncryptionWithBouncyCastleMutator.USE_MD5_FOR_ENCRYPTION_WITH_BOUNCY_CASTLE,
        UseMD5ForEncryptionJAVAStandardMutator.USE_MD5_FOR_ENCRYPTION_JAVA_STANDARD_MUTATOR,
        HostNameVerifyToTrueMutator.HOST_NAME_VERIFY_TO_TRUE,
        DisableDOCTYPEVerificationOnXMLParserWithXMLReaderMutator.XML_PARSER_VULNERABLE_TO_XXE_WITH_XMLREADER,
        DisableDOSVerificationOnXMLParserWithSAXMutator.XML_PARSER_VULNERABLE_TO_DOS_WITH_SAX,
        DisableDOSVerificationOnXMLParserWithXMLReaderMutator.XML_PARSER_VULNERABLE_TO_DOS_WITH_XMLREADER,
        DisableDOCTYPEVerificationOnXMLParserWithSAXMutator.XML_PARSER_VULNERABLE_TO_XXE_WITH_SAX,
        RemoveSSLInSocketMutator.REMOVE_SECURE_SOCKET_MUTATOR,
        CookieSecureFlagDisableMutator.REMOVE_SECURE_FLAG_MUTATOR,
        CookieHttpOnlyFlagDisableMutator.REMOVE_HTTPONLY_FLAG_MUTATOR,
        RSAWithShortKeyMutator.RSA_WITH_SHORT_KEY_MUTATOR,
        UseBLOWFISHWithShortKeyMutator.USE_BLOWFISH_WITH_SHORT_KEY,
        SQLInjectionOKWithJDBCMutator.SQL_INJECTION_OK_WITH_JDBC,
        // NEWUseDESForSymmetricEncryptionMutator.USE_DES_FOR_SYMMETRIC_ENCRYPTION,
        UseECBInSymmetricEncryptionMutator.USE_ECB_IN_SYMMETRIC_ENCRYPTION,
        PatternMatchesAnythingMutator.PATTERN_MATCHES_ANYTHING_MUTATOR,
        StringMatcherMatchesAnythingMutator.STRING_MATCHER_MATCHES_ANYTHING_MUTATOR);
  }

  /**
   * Proposed new defaults - replaced the RETURN_VALS mutator with the new more stable set
   */
  public static Collection<MethodMutatorFactory> newDefaults() {
    return combine(group(InvertNegsMutator.INVERT_NEGS_MUTATOR,
        MathMutator.MATH_MUTATOR,
        VoidMethodCallMutator.VOID_METHOD_CALL_MUTATOR,
        NegateConditionalsMutator.NEGATE_CONDITIONALS_MUTATOR,
        ConditionalsBoundaryMutator.CONDITIONALS_BOUNDARY_MUTATOR,
        IncrementsMutator.INCREMENTS_MUTATOR), betterReturns());
  }


  public static Collection<MethodMutatorFactory> betterReturns() {
    return group(BooleanTrueReturnValsMutator.BOOLEAN_TRUE_RETURN,
        BooleanFalseReturnValsMutator.BOOLEAN_FALSE_RETURN,
        PrimitiveReturnsMutator.PRIMITIVE_RETURN_VALS_MUTATOR,
        EmptyObjectReturnValsMutator.EMPTY_RETURN_VALUES,
        NullReturnValsMutator.NULL_RETURN_VALUES);
  }

  private static Collection<MethodMutatorFactory> group(
      final MethodMutatorFactory... ms) {
    return Arrays.asList(ms);
  }

  public static Collection<MethodMutatorFactory> byName(final String name) {
    return FCollection.map(MUTATORS.get(name),
        Prelude.id(MethodMutatorFactory.class));
  }

  private static void add(final String key, final MethodMutatorFactory value) {
    MUTATORS.put(key, Collections.singleton(value));
  }

  private static void addGroup(final String key,
      final Iterable<MethodMutatorFactory> value) {
    MUTATORS.put(key, value);
  }

  public static Collection<MethodMutatorFactory> fromStrings(
      final Collection<String> names) {
    final Set<MethodMutatorFactory> unique = new TreeSet<>(
        compareId());

    FCollection.flatMapTo(names, fromString(), unique);
    return unique;
  }

  private static Comparator<? super MethodMutatorFactory> compareId() {
    return (o1, o2) -> o1.getGloballyUniqueId().compareTo(o2.getGloballyUniqueId());
  }

  private static Function<String, Iterable<MethodMutatorFactory>> fromString() {
    return a -> {
      final Iterable<MethodMutatorFactory> i = MUTATORS.get(a);
      if (i == null) {
        throw new PitHelpError(Help.UNKNOWN_MUTATOR, a);
      }
      return i;
    };
  }

}
