/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.parser.cyclonedx;

import alpine.common.logging.Logger;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.dependencytrack.persistence.QueryManager;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;



public class CycloneDXExporter {

    private static final Logger LOGGER = Logger.getLogger(CycloneDXExporter.class);

    public enum Format {
        JSON,
        XML
    }

    public enum Variant {
        INVENTORY,
        INVENTORY_WITH_VULNERABILITIES,
        VDR,
        VEX
    }

    private final Logger logger;
    private final QueryManager qm;
    private final CycloneDXExporter.Variant variant;

    public CycloneDXExporter(final CycloneDXExporter.Variant variant, final QueryManager qm) {
        this.logger = Logger.getLogger(getClass());
        this.variant = variant;
        this.qm = qm;
    }

    public Bom create(final Project project) {
        LOGGER.info("[CycloneDX Export] Getting all components for project '%s' [ID: %s]".formatted(project.getName(), project.getId()));
        final List<Component> components = qm.getAllComponents(project);

        LOGGER.info("[CycloneDX Export] Retrieved %d components".formatted(components.size()));

        LOGGER.info("[CycloneDX Export] Getting all service components for project '%s' [ID: %s]".formatted(project.getName(), project.getId()));
        final List<ServiceComponent> services = qm.getAllServiceComponents(project);

        LOGGER.info("[CycloneDX Export] Retrieved %d service components".formatted(services.size()));

        List<Finding> findings = null;

        if (variant == Variant.INVENTORY_WITH_VULNERABILITIES || variant == Variant.VDR || variant == Variant.VEX) {
            LOGGER.info("[CycloneDX Export] Getting findings for project '%s' [ID: %s]".formatted(project.getName(), project.getId()));
            findings = qm.getFindings(project, true);
            LOGGER.info("[CycloneDX Export] Retrieved %d findings".formatted(findings.size()));
        }

        LOGGER.info("[CycloneDX Export] Preparing to create BOM");
        return create(components, services, findings, project);
    }

    public Bom create(final Component component) {
        LOGGER.info("[CycloneDX Export] Creating BOM for single component [ID: %s]".formatted(component.getId()));
        final List<Component> components = new ArrayList<>();
        components.add(component);
        return create(components, null, null, null);
    }

    private Bom create(List<Component> components, final List<ServiceComponent> services, final List<Finding> findings, final Project project) {
        if (Variant.VDR == variant) {
            LOGGER.info("[CycloneDX Export - Inner] Filtering components with vulnerabilities for VDR");
            List<Component> filteredComponents = new ArrayList<>();
            for (Component component : components) {
                if (!component.getVulnerabilities().isEmpty()) {
                    filteredComponents.add(component);
                }
            }
            components = filteredComponents;
            LOGGER.info("[CycloneDX Export - Inner] %d components remaining after filtering".formatted(components.size()));
        }

        LOGGER.info("[CycloneDX Export - Inner] Converting Components");
        final List<org.cyclonedx.model.Component> cycloneComponents =
                (Variant.VEX != variant && components != null) ? new ArrayList<>() : null;
        
        if (cycloneComponents != null) {
            for (Component component : components) {
                LOGGER.info("[CycloneDX Export - Inner] Converting component: %s".formatted(component.getName()));
                org.cyclonedx.model.Component cycloneComponent = ModelConverter.convert(qm, component);
                LOGGER.info("[CycloneDX Export - Inner] Converted component: %s".formatted(cycloneComponent.getName()));
                cycloneComponents.add(cycloneComponent);
            }
        } 

        LOGGER.info("[CycloneDX Export - Inner] Converting Services");
        final List<org.cyclonedx.model.Service> cycloneServices =
                (Variant.VEX != variant && services != null) ? new ArrayList<>() : null;

        if (cycloneServices != null) {
            for (ServiceComponent service : services) {
                cycloneServices.add(ModelConverter.convert(qm, service));
            }
        }

        LOGGER.info("[CycloneDX Export - Inner] Setting up BOMs");
        final Bom bom = new Bom();
        bom.setSerialNumber("urn:uuid:" + UUID.randomUUID());
        bom.setVersion(1);

        if (project != null) {
            bom.setMetadata(ModelConverter.createMetadata(project));
            LOGGER.info("[CycloneDX Export - Inner] Metadata set for project '%s'".formatted(project.getName()));
        }

        bom.setComponents(cycloneComponents);
        bom.setServices(cycloneServices);
        bom.setVulnerabilities(ModelConverter.generateVulnerabilities(qm, variant, findings));

        if (cycloneComponents != null) {
            LOGGER.info("[CycloneDX Export - Inner] Generating dependencies for %d components".formatted(cycloneComponents.size()));
            bom.setDependencies(ModelConverter.generateDependencies(project, components));
        }

        LOGGER.info("[CycloneDX Export - Inner] BOM creation complete");
        return bom;
    }

    public String export(final Bom bom, final Format format) throws GeneratorException {
        LOGGER.info("[CycloneDX Export - Export] Exporting BOM in %s format".formatted(format.name()));
        String result = null;

        if (Format.JSON == format) {
            LOGGER.info("[CycloneDX Export - Export] Exporting JSON");
            result = BomGeneratorFactory.createJson(Version.VERSION_15, bom).toJsonString();
        } else {
            LOGGER.info("[CycloneDX Export - Export] Exporting XML");
            result = BomGeneratorFactory.createXml(Version.VERSION_15, bom).toXmlString();
        }

        LOGGER.info("[CycloneDX Export - Export] Export complete");
        return result;
    }
}
