import { expect, expectTypeOf, it } from 'vitest';
import type { AttackPotentialResistance, KeyAttestationOptions } from './types';
import type { WeBuildKeyAttestationOptions } from './WeBuildProfile';

it('expresses supported assurance values and required WE BUILD status in types', () => {
	expectTypeOf<'iso_18045_basic'>().toExtend<AttackPotentialResistance>();
	expectTypeOf<'high'>().not.toExtend<AttackPotentialResistance>();
	expectTypeOf<WeBuildKeyAttestationOptions>().toExtend<KeyAttestationOptions>();
	expectTypeOf<WeBuildKeyAttestationOptions['key_storage_status']>().not.toEqualTypeOf<undefined>();
	const assurance: AttackPotentialResistance = 'iso_18045_basic';
	expect(assurance).toBe('iso_18045_basic');
});
