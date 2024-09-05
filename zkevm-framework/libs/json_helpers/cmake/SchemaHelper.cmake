# Set variables depending on CMAKE_CURRENT_LIST_DIR outside functions,
# otherwise the value will be a path to a caller list
set(SCRIPT_PATH "${CMAKE_CURRENT_LIST_DIR}/SchemaScript.cmake")
set(TEMPLATE_PATH "${CMAKE_CURRENT_LIST_DIR}/../schema.def.in")

function(generate_schema_include target_name schema_path)
    if (NOT IS_ABSOLUTE ${schema_path})
        set(schema_path ${CMAKE_CURRENT_SOURCE_DIR}/${schema_path})
    endif()
    get_filename_component(SCHEMA_NAME ${schema_path} NAME_WE)
    set(DEF_FILE ${CMAKE_CURRENT_BINARY_DIR}/include/${SCHEMA_NAME}.def)
    # Generate include guard name for schema include file
    file(RELATIVE_PATH RP ${CMAKE_BINARY_DIR} ${DEF_FILE})
    string(TOUPPER ${RP} UPPER_PATH)
    string(REGEX REPLACE "[/\.$]" "_" INCLUDE_GUARD_NAME ${UPPER_PATH})

    # Add a target to regenerate schema header every time when the schema file is changed
    add_custom_command(
        OUTPUT ${DEF_FILE}
        COMMAND ${CMAKE_COMMAND} -D INCLUDE_GUARD=${INCLUDE_GUARD_NAME} -D SCHEMA_PATH=${schema_path}
                                 -D OUTPUT_PATH=${DEF_FILE} -P ${SCRIPT_PATH}
        DEPENDS ${schema_path}
        DEPENDS ${TEMPLATE_PATH}
    )
    add_custom_target(${target_name} DEPENDS ${DEF_FILE})
endfunction()
