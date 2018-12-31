package org.apereo.cas.interrupt;

import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.util.ResourceUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.val;
import org.hjson.JsonValue;
import org.springframework.core.io.Resource;
import org.springframework.webflow.execution.RequestContext;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * This is {@link JsonResourceInterruptInquirer}.
 *
 * @author Misagh Moayyed
 * @since 5.2.0
 */
public class JsonResourceInterruptInquirer extends BaseInterruptInquirer {

    private static final ObjectMapper MAPPER = new ObjectMapper().findAndRegisterModules();

    private final Resource resource;
    private Map<String, InterruptResponse> interrupts;

    public JsonResourceInterruptInquirer(final Resource resource) {
        this.resource = resource;
    }

    @Override
    public InterruptResponse inquireInternal(final Authentication authentication, final RegisteredService registeredService,
                                             final Service service, final Credential credential,
                                             final RequestContext requestContext) {
        val user = authentication.getPrincipal().getId();
        readResourceForInterrupts();
        if (interrupts.containsKey(user)) {
            return interrupts.get(user);
        }
        return InterruptResponse.none();
    }

    @SneakyThrows
    private void readResourceForInterrupts() {
        this.interrupts = new LinkedHashMap<>();
        if (ResourceUtils.doesResourceExist(resource)) {
            try (val reader = new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8)) {
                final TypeReference<Map<String, InterruptResponse>> personList = new TypeReference<>() {
                };
                this.interrupts = MAPPER.readValue(JsonValue.readHjson(reader).toString(), personList);
            }
        }
    }
}
